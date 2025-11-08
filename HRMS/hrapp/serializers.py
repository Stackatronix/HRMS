from datetime import date, datetime
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from django.utils.dateparse import parse_datetime
from django.utils import timezone
import re
from .models import (
    OTP,
    Department,
    Employee,
    PaymentProfile,
    Attendance,
    LeaveRequest,
    LeaveBalance,
    PayrollPeriod,
    Payroll,
    CustomUser,
)

User = get_user_model()


class UserSignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ["email", "password", "confirm_password"]

    def validate_email(self, value):
        user = CustomUser.objects.filter(email=value).first()
        if user:
            if user.is_verified:
                raise serializers.ValidationError("Email is already registered.")
            else:
                raise serializers.ValidationError(
                    "Email is already registered but not verified. Please check your email or contact support."
                )
        return value

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if not re.search(r"[A-Z]", value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r"\d", value):
            raise serializers.ValidationError("Password must contain at least one number.")
        if not re.search(r"[@$!%*?&^#()\-_=+{};:,<.>]", value):
            raise serializers.ValidationError("Password must contain at least one special character.")
        return value

    def validate(self, data):
        if data.get("password") != data.get("confirm_password"):
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        return data

    def create(self, validated_data):
        validated_data.pop("confirm_password")
        return CustomUser.objects.create_user(
            email=validated_data["email"], password=validated_data["password"], role="employee"
        )


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    def validate(self, data):
        user = authenticate(email=data["email"], password=data["password"])
        if not user:
            raise serializers.ValidationError("Invalid email or password")
        if not user.is_active:
            raise serializers.ValidationError("User not activated. Please verify OTP.")
        data["user"] = user
        return data


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["id", "email", "role", "is_active"]
        read_only_fields = fields


class DepartmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Department
        fields = ["id", "name"]
        read_only_fields = ["id"]


class EmployeeSerializer(serializers.ModelSerializer):
    user_id = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), source="user", write_only=True)
    department_id = serializers.PrimaryKeyRelatedField(queryset=Department.objects.all(), source="department", write_only=True)
    user = serializers.SerializerMethodField()
    department = serializers.SerializerMethodField()

    class Meta:
        model = Employee
        fields = [
            "id",
            "user_id",
            "user",
            "fullname",
            "department_id",
            "department",
            "designation",
            "date_of_joining",
            "bank_account",
            "ifsc_code",
            "is_verified",
            "pending_update",
        ]
        read_only_fields = ["id", "is_verified", "pending_update"]
        
    def validate_user_id(self, value):
        if Employee.objects.filter(user=value).exists():
            raise serializers.ValidationError("This user is already linked to an employee profile.")
        return value
    def validate_department_id(self, value):
        if not Department.objects.filter(id=value.id).exists():
            raise serializers.ValidationError("Department does not exist.")
        return value
    def get_user(self, obj):
        return {"id": obj.user.id, "email": obj.user.email} if obj.user else None

    def get_department(self, obj):
        return {"id": obj.department.id, "name": obj.department.name} if obj.department else None


class EmployeeSelfUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Employee
        fields = ["fullname", "bank_account", "ifsc_code"]
        extra_kwargs = {f: {"required": False} for f in fields}
    def validate(self, attrs):
        if not attrs:
            raise serializers.ValidationError("At least one field must be provided for update.")
        return attrs

class PaymentProfileSerializer(serializers.ModelSerializer):
    employee_id = serializers.PrimaryKeyRelatedField(queryset=Employee.objects.all(), source="employee")
    employee = serializers.SerializerMethodField()

    class Meta:
        model = PaymentProfile
        fields = ["id", "employee_id", "employee", "base_salary", "overtime_payment", "last_updated"]
        read_only_fields = ["id", "last_updated"]

    def get_employee(self, obj):
        return {"id": obj.employee.id, "fullname": obj.employee.fullname} if obj.employee else None


class AttendanceSerializer(serializers.ModelSerializer):
    employee_id = serializers.PrimaryKeyRelatedField(queryset=Employee.objects.all(), source="employee")
    employee = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Attendance
        fields = [
            "id",
            "employee_id",
            "employee",
            "date",
            "check_in",
            "check_out",
            "status",
            "hours_worked",
            "overtime_hours",
        ]
        read_only_fields = ["id", "hours_worked", "overtime_hours","status"]

    def get_employee(self, obj):
        return {"id": obj.employee.id, "fullname": obj.employee.fullname} if obj.employee else None

    def validate_check_in(self, value):
        if isinstance(value, str):
            parsed = parse_datetime(value)
            if not parsed:
                raise serializers.ValidationError("Invalid datetime format. Use ISO 8601 format.")
            return parsed
        elif isinstance(value, datetime):
            return value
        raise serializers.ValidationError("Invalid datetime format. Use ISO 8601 format.")

    def validate_check_out(self, value):
        if isinstance(value, str):
            parsed = parse_datetime(value)
            if not parsed:
                raise serializers.ValidationError("Invalid datetime format. Use ISO 8601 format.")
            return parsed
        elif isinstance(value, datetime):
            return value
        raise serializers.ValidationError("Invalid datetime format. Use ISO 8601 format.")


class LeaveRequestSerializer(serializers.ModelSerializer):
    employee = serializers.SerializerMethodField(read_only=True)
    action_by = serializers.SerializerMethodField(read_only=True)
    days = serializers.IntegerField(read_only=True)

    class Meta:
        model = LeaveRequest
        fields = [
            "id",
            "employee",
            "type",
            "start_date",
            "end_date",
            "reason",
            "status",
            "created_at",
            "action_by",
            "is_paid",
            "days",
        ]
        read_only_fields = ["id", "status", "created_at", "action_by", "is_paid", "days"]

    def get_employee(self, obj):
        return {"id": obj.employee.id, "fullname": obj.employee.fullname} if obj.employee else None

    def get_action_by(self, obj):
        return {"id": obj.action_by.id, "email": obj.action_by.email} if obj.action_by else None

    def validate(self, attrs):
        request = self.context["request"]
        user = request.user
        if not hasattr(user, "employee"):
            raise serializers.ValidationError("The user is not linked to any employee profile.")
        start = attrs.get("start_date")
        end = attrs.get("end_date")
        if start and end and start > end:
            raise serializers.ValidationError("Start date cannot be greater than end date.")
        existing = LeaveRequest.objects.filter(employee=user.employee, start_date=start, end_date=end).first()
        if existing and existing.status in ["approved", "rejected", "pending"]:
            raise serializers.ValidationError(
                f"A leave request from {start} to {end} already exists with status '{existing.status}'."
            )
        return attrs

    def create(self, validated_data):
        user = self.context["request"].user
        validated_data["employee"] = user.employee
        leave_type = validated_data.get("type")
        validated_data["is_paid"] = False if leave_type == "Unpaid" else True
        return super().create(validated_data)


class LeaveBalanceSerializer(serializers.ModelSerializer):
    employee = serializers.SerializerMethodField()

    class Meta:
        model = LeaveBalance
        fields = ["id", "employee", "casual", "sick"]
        read_only_fields = ["id", "employee"]

    def get_employee(self, obj):
        return {"id": obj.employee.id, "fullname": obj.employee.fullname} if obj.employee else None


class PayrollPeriodSerializer(serializers.ModelSerializer):
    class Meta:
        model = PayrollPeriod
        fields = ["id", "start", "end", "is_closed"]
        read_only_fields = ["id", "is_closed"]

    def validate(self, attrs):
        start = attrs.get("start")
        end = attrs.get("end")
        if start is None or end is None:
            raise serializers.ValidationError("Both 'start' and 'end' dates are required.")
        if not isinstance(start, date) or not isinstance(end, date):
            raise serializers.ValidationError("'start' and 'end' must be valid date objects (YYYY-MM-DD).")
        if start > end:
            raise serializers.ValidationError("'start' date cannot be later than 'end' date.")
        return attrs


class PayrollSerializer(serializers.ModelSerializer):
    employee_id = serializers.PrimaryKeyRelatedField(queryset=Employee.objects.all(), source="employee")
    employee = serializers.SerializerMethodField()
    period = serializers.PrimaryKeyRelatedField(queryset=PayrollPeriod.objects.all())

    class Meta:
        model = Payroll
        fields = [
            "id",
            "employee_id",
            "employee",
            "period",
            "gross",
            "overtime_pay",
            "deductions",
            "net",
            "currency",
            "line_items",
            "payslip_file",
            "status",
            "generated_at",
            "is_generating",
        ]
        read_only_fields = ["id", "net", "payslip_file", "generated_at", "is_generating"]

    def get_employee(self, obj):
        return {"id": obj.employee.id, "fullname": obj.employee.fullname} if obj.employee else None


class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True)
    otp = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get("email")
        code = data.get("otp")
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "User not found"})
        otp_obj = OTP.objects.filter(user=user, code=code, is_used=False).order_by("-created_at").first()
        if not otp_obj:
            raise serializers.ValidationError({"otp": "Invalid OTP"})
        if otp_obj.expiration_time < timezone.now():
            raise serializers.ValidationError({"otp": "OTP expired"})
        data["user"] = user
        data["otp_obj"] = otp_obj
        return data
