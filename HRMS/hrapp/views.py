from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from django.http import FileResponse, Http404
from django.db import transaction
from rest_framework import viewsets, permissions, views
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from .tasks import generate_payslip_background
from .models import (
    Department, Employee, PaymentProfile, Attendance,
    LeaveRequest, LeaveBalance, PayrollPeriod, Payroll, OTP
)
from .serializers import (
    DepartmentSerializer, EmployeeSerializer, EmployeeSelfUpdateSerializer,
    PaymentProfileSerializer, AttendanceSerializer,
    LeaveRequestSerializer, PayrollPeriodSerializer, PayrollSerializer,
    UserLoginSerializer, UserSerializer, UserSignupSerializer,
)
from .permissions import RolePermission, IsOwnerOrRoleAllowed


User = get_user_model()

class UserSignupView(views.APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        serializer = UserSignupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User registered. Verify OTP sent to email."}, status=201)
        return Response(serializer.errors, status=400)

class UserLoginView(views.APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data["user"]
            refresh = RefreshToken.for_user(user)
            response = Response({"message":"Login successful","user":{"email":user.email,"role":user.role}})
            response.set_cookie(
                key="access_token", value=str(refresh.access_token), httponly=True,
                secure=(not settings.DEBUG), samesite="Lax", max_age=15*60
            )
            response.set_cookie(
                key="refresh_token", value=str(refresh), httponly=True,
                secure=(not settings.DEBUG), samesite="Lax", max_age=7*24*60*60
            )
            return response
        return Response(serializer.errors, status=400)

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
            return Response({"error":"No refresh token"}, status=401)
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
            return Response({"error":"Invalid or expired refresh token"}, status=401)

@api_view(["POST"])
@permission_classes([permissions.AllowAny])
def verify_otp(request):
    email = request.data.get("email")
    code = request.data.get("otp")
    if not email or not code:
        return Response({"detail":"email and otp are required"}, status=400)
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"detail":"user not found"}, status=404)
    otp_obj = OTP.objects.filter(user=user, code=code, is_used=False).order_by("-created_at").first()
    if not otp_obj:
        return Response({"detail":"invalid otp"}, status=400)
    if otp_obj.expiration_time < timezone.now():
        return Response({"detail":"otp expired"}, status=400)
    user.is_active = True
    user.save(update_fields=["is_active"])
    otp_obj.is_used = True
    otp_obj.save(update_fields=["is_used"])
    return Response({"detail":"account verified"})

class UserManageViewSet(viewsets.ModelViewSet):
    queryset = User.objects.filter(is_superuser=False) 
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
        if request.user.role != "employee":
            return Response({"detail":"Only employees can use /me"}, status=400)
        try:
            emp = Employee.objects.get(user=request.user)
        except Employee.DoesNotExist:
            return Response({"detail":"Employee profile missing"}, status=404)

        if request.method.lower() == "get":
            return Response(EmployeeSerializer(emp).data)

        ser = EmployeeSelfUpdateSerializer(emp, data=request.data, partial=True)
        if ser.is_valid():
            ser.save()
            emp.pending_update = True
            emp.is_verified = False
            emp.save(update_fields=["pending_update","is_verified"])
            return Response(EmployeeSerializer(emp).data)
        return Response(ser.errors, status=400)

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
        if request.user.role != "employee":
            return Response({"detail":"Only employees can use /payment-profiles/mine"}, status=400)
        try:
            emp = Employee.objects.get(user=request.user)
        except Employee.DoesNotExist:
            return Response({"detail":"Employee profile missing"}, status=404)
        pp = getattr(emp, "payment_profile", None)
        if not pp:
            return Response({"detail":"Payment profile missing"}, status=404)
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
                return Response({"detail":"Employee not found"}, status=404)
        else:
            employee = Employee.objects.filter(user=request.user).first()
            if not employee:
                return Response({"detail":"Employee profile missing"}, status=400)
        att, created = Attendance.objects.get_or_create(
            employee=employee, date=today,
            defaults={"check_in": now, "status":"present"}
        )
        if not created and att.check_in:
            return Response({"detail":"Already checked in"}, status=400)
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
                return Response({"detail":"Employee not found"}, status=404)
        else:
            employee = Employee.objects.filter(user=request.user).first()
            if not employee:
                return Response({"detail":"Employee profile missing"}, status=400)

        att = Attendance.objects.filter(employee=employee, date=today).first()
        if not att or not att.check_in:
            return Response({"detail":"No check-in record for today"}, status=400)
        if att.check_out:
            return Response({"detail":"Already checked out"}, status=400)
        if att.check_in > now:
            return Response({"detail":"Check-out time cannot be before check-in time"}, status=400)
        
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
            return Response({"error": "check_out is required (ISO format)"}, status=400)

        attendance.check_out = checkout_time
        attendance.status = "present" 
        attendance.save()
        return Response({"detail": "Checkout updated manually"} , status=200)

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
                    return Response({"detail": "Not enough casual leave balance."}, status=400)
                lb.casual -= lr.days
            elif lr.type == "SICK":
                if lb.sick < lr.days:
                    return Response({"detail": "Not enough sick leave balance."}, status=400)
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
            return Response({"detail": "Not allowed"}, status=403)
        if lr.status != "PENDING":
            return Response({"detail": "Only pending requests can be cancelled."}, status=400)
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
            return Response({"detail": "Not allowed"}, status=403)
        updated = Payroll.objects.filter(id=payroll.id, is_generating=False).update(is_generating=True)
        if not updated:
            return Response({"detail": "Payslip is being generated. Please check later."}, status=400)
        
        generate_payslip_background(payroll.id)

        return Response({"detail": "Payslip generation started. Please check later."})
    @action(detail=True, methods=["get"])
    def download_payslip(self, request, pk=None):
        payroll = self.get_object()
        if not payroll.payslip_file:
            raise Http404("Payslip not ready.")
        return FileResponse(payroll.payslip_file.open("rb"), as_attachment=True,
                           filename=payroll.payslip_file.name.split("/")[-1])
