from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from django.http import FileResponse, Http404
from django.db import transaction
from rest_framework import viewsets, permissions, views,status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from .tasks import generate_payslip_background
from .models import (
    Department, Employee, PaymentProfile, Attendance,
    LeaveRequest, LeaveBalance, PayrollPeriod, Payroll
)

from .serializers import (
    DepartmentSerializer, EmployeeSerializer, EmployeeSelfUpdateSerializer,
    PaymentProfileSerializer, AttendanceSerializer,
    LeaveRequestSerializer, PayrollPeriodSerializer, PayrollSerializer,
    UserLoginSerializer, UserSerializer, UserSignupSerializer, VerifyOTPSerializer,
)

from .permissions import RolePermission, IsOwnerOrRoleAllowed
from drf_yasg.utils import swagger_auto_schema

User = get_user_model()

class UserSignupView(views.APIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(request_body=UserSignupSerializer)
    def post(self, request):
        serializer = UserSignupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User registered. Verify OTP sent to email."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(views.APIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(request_body=UserLoginSerializer)  
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data["user"]
            refresh = RefreshToken.for_user(user)
            response = Response({"message":"Login successful","user":{"email":user.email,"role":user.role}}, status=status.HTTP_200_OK)
            response.set_cookie(
                key="access_token", value=str(refresh.access_token), httponly=True,
                secure=(not settings.DEBUG), samesite="Lax", max_age=15*60
            )
            response.set_cookie(
                key="refresh_token", value=str(refresh), httponly=True,
                secure=(not settings.DEBUG), samesite="Lax", max_age=7*24*60*60
            )
            return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLogoutView(views.APIView):
    def post(self, request):
        resp = Response({"message":"Logged out"})
        resp.delete_cookie("access_token")
        resp.delete_cookie("refresh_token")
        return resp

class CookieTokenRefreshView(views.APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        rt = request.COOKIES.get("refresh_token")
        if not rt:
            return Response({"error":"No refresh token"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            refresh = RefreshToken(rt)
            new_access = str(refresh.access_token)
            response = Response({"message":"Token refreshed"})
            response.set_cookie(
                key="access_token", value=new_access, httponly=True,
                secure=(not settings.DEBUG), samesite="Lax", max_age=15*60
            )
            return response
        except Exception:
            return Response({"error":"Invalid or expired refresh token"}, status=status.HTTP_401_UNAUTHORIZED)

class VerifyOTPView(views.APIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(request_body=VerifyOTPSerializer)
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data["user"]
            otp_obj = serializer.validated_data["otp_obj"]

            user.is_active = True
            user.save(update_fields=["is_active"])

            otp_obj.is_used = True
            otp_obj.save(update_fields=["is_used"])

            return Response({"detail": "Account verified successfully"}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserManageViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated, RolePermission]
    allowed_roles = ["hr"]


class DepartmentViewSet(viewsets.ModelViewSet):
    queryset = Department.objects.all()
    serializer_class = DepartmentSerializer
    allowed_roles = ["hr"]
    permission_classes = [permissions.IsAuthenticated, RolePermission]

class EmployeeViewSet(viewsets.ModelViewSet):
    queryset = Employee.objects.select_related("user","department")
    serializer_class = EmployeeSerializer
    allowed_roles_by_action = {
        "list": ["hr"], "retrieve": ["hr"], "create": ["hr"], "destroy": ["hr"],
        "approve": ["hr"], "payment_profile": ["hr"], 
        
    }
    permission_classes = [permissions.IsAuthenticated, RolePermission]

    @action(detail=False, methods=["get","patch"], url_path="me")
    def me(self, request):
        try:
            emp = Employee.objects.get(user=request.user)
        except Employee.DoesNotExist:
            return Response({"detail":"Employee profile missing"}, status=status.HTTP_404_NOT_FOUND)

        if request.method.lower() == "get":
            return Response(EmployeeSerializer(emp).data)

        ser = EmployeeSelfUpdateSerializer(emp, data=request.data, partial=True)
        if ser.is_valid():
            ser.save()
            emp.pending_update = True
            emp.is_verified = False
            emp.save(update_fields=["pending_update","is_verified"])
            return Response(EmployeeSerializer(emp).data)
        return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=["post"])
    def approve(self, request, pk=None):
        emp = self.get_object()
        emp.is_verified = True
        emp.pending_update = False
        emp.save(update_fields=["is_verified","pending_update"])
        return Response({"detail":"Employee profile verified"})

class PaymentProfileViewSet(viewsets.ModelViewSet):
    queryset = PaymentProfile.objects.select_related("employee","employee__user")
    serializer_class = PaymentProfileSerializer
    allowed_roles_by_action = {
        "list": ["hr"], "retrieve": ["hr"], "create": ["hr"], "update": ["hr"], "partial_update": ["hr"], "destroy": ["hr"],
        "mine": None,
    }
    permission_classes = [permissions.IsAuthenticated, RolePermission]

    @action(detail=False, methods=["get"])
    def mine(self, request):
        try:
            emp = Employee.objects.get(user=request.user)
        except Employee.DoesNotExist:
            return Response({"detail":"Employee profile missing"}, status=status.HTTP_404_NOT_FOUND)
        pp = getattr(emp, "payment_profile", None)
        if not pp:
            return Response({"detail":"Payment profile missing"}, status=status.HTTP_404_NOT_FOUND)
        return Response(PaymentProfileSerializer(pp).data)

class AttendanceViewSet(viewsets.ModelViewSet):
    queryset = Attendance.objects.select_related("employee","employee__user")
    serializer_class = AttendanceSerializer
    allowed_roles_by_action = {
        "list": ["hr"], "retrieve": ["hr"], "create": ["hr"], "update": ["hr"], "partial_update": ["hr"], "destroy": ["hr"],
        "check_in": None, "check_out": None,"manual_checkout": ["hr"],
    }
    permission_classes = [permissions.IsAuthenticated, RolePermission]

    def get_queryset(self):
        qs = super().get_queryset()
        if getattr(self, "action", None) in ("list","retrieve"):
            if not (self.request.user.is_authenticated and self.request.user.role == "hr"):
                qs = qs.filter(employee__user=self.request.user)
        return qs

    @action(detail=False, methods=["post"])
    def check_in(self, request):
        now = timezone.now()
        today = now.date()
        if request.user.role == "hr" and request.data.get("employee_id"):
            employee = Employee.objects.filter(pk=request.data["employee_id"]).first()
            if not employee:
                return Response({"detail":"Employee not found"}, status=status.HTTP_404_NOT_FOUND)
        else:
            employee = Employee.objects.filter(user=request.user).first()
            if not employee:
                return Response({"detail":"Employee profile missing"}, status=status.HTTP_400_BAD_REQUEST)
        att, created = Attendance.objects.get_or_create(
            employee=employee, date=today,
            defaults={"check_in": now, "status":"present"}
        )
        if not created and att.check_in:
            return Response({"detail":"Already checked in"}, status=status.HTTP_400_BAD_REQUEST)
        att.check_in = now
        if not att.status: att.status = "present"
        att.save()
        return Response(self.get_serializer(att).data)

    @action(detail=False, methods=["post"])
    def check_out(self, request):
        now = timezone.now()
        today = now.date()
        if request.user.role == "hr" and request.data.get("employee_id"):
            employee = Employee.objects.filter(pk=request.data["employee_id"]).first()
            if not employee:
                return Response({"detail":"Employee not found"}, status=status.HTTP_404_NOT_FOUND)
        else:
            employee = Employee.objects.filter(user=request.user).first()
            if not employee:
                return Response({"detail":"Employee profile missing"}, status=status.HTTP_400_BAD_REQUEST)

        att = Attendance.objects.filter(employee=employee, date=today).first()
        if not att or not att.check_in:
            return Response({"detail":"No check-in record for today"}, status=status.HTTP_400_BAD_REQUEST)
        if att.check_out:
            return Response({"detail":"Already checked out"}, status=status.HTTP_400_BAD_REQUEST)
        if att.check_in > now:
            return Response({"detail":"Check-out time cannot be before check-in time"}, status=status.HTTP_400_BAD_REQUEST)
        
        att.check_out = now
        local = timezone.localtime(att.check_in)
        work_start_str = settings.COMPANY_CONFIG.get("work_hours", {}).get("start", "09:00")
        work_start = datetime.strptime(work_start_str, "%H:%M")
        late_time = (work_start + timedelta(minutes=15)).time()
        if local.time() > late_time:
            att.status = "late"
        else:
            att.status = "present"
        att.save()
        return Response(self.get_serializer(att).data)

    @action(detail=True, methods=["post"])
    def manual_checkout(self, request, pk=None):
        attendance = self.get_object()
        checkout_time = request.data.get("check_out")
        
        if not checkout_time:
            return Response({"error": "check_out is required (ISO format)"}, status=status.HTTP_400_BAD_REQUEST)

        attendance.check_out = checkout_time
        attendance.status = "present" 
        attendance.save()
        return Response({"detail": "Checkout updated manually"} , status=status.HTTP_200_OK)

class LeaveRequestViewSet(viewsets.ModelViewSet):
    queryset = LeaveRequest.objects.select_related("employee","action_by")
    serializer_class = LeaveRequestSerializer
    allowed_roles_by_action = {
        "approve": ["hr"],
        "reject": ["hr"],
        "cancel": ["employee"],
    }
    permission_classes = [permissions.IsAuthenticated, RolePermission]

    def get_queryset(self):
        qs = super().get_queryset()
        if self.request.user.role != "hr":
            qs = qs.filter(employee__user=self.request.user)
        return qs

    def perform_create(self, serializer):
        employee = Employee.objects.get(user=self.request.user)
        serializer.save(employee=employee)
    
    @transaction.atomic
    @action(detail=True, methods=["post"])
    def approve(self, request, pk=None):
        lr = self.get_object()
        lr.status = "APPROVED"
        lr.action_by = request.user
        
        if lr.is_paid:
            lb, _ = LeaveBalance.objects.get_or_create(employee=lr.employee)
            
            if lr.type == "CASUAL":
                if lb.casual < lr.days: 
                    return Response({"detail": "Not enough casual leave balance."}, status=status.HTTP_400_BAD_REQUEST)
                lb.casual -= lr.days
            elif lr.type == "SICK":
                if lb.sick < lr.days:
                    return Response({"detail": "Not enough sick leave balance."}, status=status.HTTP_400_BAD_REQUEST)
                lb.sick -= lr.days
            lb.save()
            
        lr.save() 
        return Response(self.get_serializer(lr).data)

    @action(detail=True, methods=["post"])
    def reject(self, request, pk=None):
        lr = self.get_object()
        lr.status = "REJECTED"
        lr.action_by = request.user
        lr.save()
        return Response(self.get_serializer(lr).data)
    
    @action(detail=True, methods=["post"])
    def cancel(self, request, pk=None):
        lr = self.get_object()
        if lr.employee.user != request.user:
            return Response({"detail": "Not allowed"}, status=status.HTTP_403_FORBIDDEN)
        if lr.status != "PENDING":
            return Response({"detail": "Only pending requests can be cancelled."}, status=status.HTTP_400_BAD_REQUEST)
        lr.status = "CANCELLED"
        lr.save()
        return Response(self.get_serializer(lr).data)

class PayrollPeriodViewSet(viewsets.ModelViewSet):
    queryset = PayrollPeriod.objects.all()
    serializer_class = PayrollPeriodSerializer
    allowed_roles = ["hr"]
    permission_classes = [permissions.IsAuthenticated, RolePermission]

class PayrollViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Payroll.objects.select_related("employee","employee__user","period")
    serializer_class = PayrollSerializer

    allowed_roles_by_action = {
        "list": ["hr"],
        "retrieve": ["hr"],
        "generate_payslip": ["hr", "employee"],
    }
    permission_classes = [permissions.IsAuthenticated, RolePermission, IsOwnerOrRoleAllowed]

    def get_queryset(self):
        qs = super().get_queryset()
        if self.request.user.role != "hr":
            qs = qs.filter(employee__user=self.request.user)
        return qs
    
    @action(detail=True, methods=["post"])
    def generate_payslip(self, request, pk=None):
        payroll = self.get_object()

        if request.user.role != "hr" and payroll.employee.user != request.user:
            return Response({"detail": "Not allowed"}, status=status.HTTP_403_FORBIDDEN)
        updated = Payroll.objects.filter(id=payroll.id, is_generating=False).update(is_generating=True)
        if not updated:
            return Response({"detail": "Payslip is being generated. Please check later."}, status=status.HTTP_400_BAD_REQUEST)

        generate_payslip_background(payroll.id)

        return Response({"detail": "Payslip generation started. Please check later."})
    @action(detail=True, methods=["get"])
    def download_payslip(self, request, pk=None):
        payroll = self.get_object()
        if not payroll.payslip_file:
            raise Http404("Payslip not ready.")
        return FileResponse(payroll.payslip_file.open("rb"), as_attachment=True,
                           filename=payroll.payslip_file.name.split("/")[-1])
