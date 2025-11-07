from datetime import date, datetime
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from .models import (
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
from django.utils.dateparse import parse_datetime
import re

User = get_user_model()



class UserSignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ["email", "password", "confirm_password",]

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
            raise serializers.ValidationError(
                "Password must be at least 8 characters long."
            )
        if not re.search(r"[A-Z]", value):
            raise serializers.ValidationError(
                "Password must contain at least one uppercase letter."
            )
        if not re.search(r"[a-z]", value):
            raise serializers.ValidationError(
                "Password must contain at least one lowercase letter."
            )
        if not re.search(r"\d", value):
            raise serializers.ValidationError(
                "Password must contain at least one number."
            )
        if not re.search(r"[@$!%*?&^#()\-_=+{};:,<.>]", value):
            raise serializers.ValidationError(
                "Password must contain at least one special character."
            )
        return value

    def validate(self, data):
        if data.get("password") != data.get("confirm_password"):
            raise serializers.ValidationError(
                {"confirm_password": "Passwords do not match."}
            )
        return data

    def create(self, validated_data):
        validated_data.pop("confirm_password")
        return CustomUser.objects.create_user(
            email=validated_data["email"],
            password=validated_data["password"],
            role="employee",
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


class DepartmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Department
        fields = ["id", "name"]


class UserMiniSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "role", "is_active"]


class EmployeeSerializer(serializers.ModelSerializer):
    user = UserMiniSerializer(read_only=True)
    user_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), source="user", write_only=True
    )
    department = DepartmentSerializer(read_only=True)
    department_id = serializers.PrimaryKeyRelatedField(
        queryset=Department.objects.all(), source="department", write_only=True
    )

    class Meta:
        model = Employee
        fields = [
            "id",
            "user",
            "user_id",
            "fullname",
            "department",
            "department_id",
            "designation",
            "date_of_joining",
            "bank_account",
            "ifsc_code",
            "is_verified",
            "pending_update",
        ]
        read_only_fields = ["is_verified", "pending_update"]


class EmployeeSelfUpdateSerializer(serializers.ModelSerializer):

    class Meta:
        model = Employee
        fields = ["fullname", "bank_account", "ifsc_code"]
        extra_kwargs = {f: {"required": False, "allow_blank": True} for f in fields}

    def update(self, instance, validated_data):
        updated = False

        for field, value in validated_data.items():
            if getattr(instance, field) != value:
                setattr(instance, field, value)
                updated = True

        if updated:
            instance.save()

        return instance


class PaymentProfileSerializer(serializers.ModelSerializer):
    employee = EmployeeSerializer(read_only=True)
    employee_id = serializers.PrimaryKeyRelatedField(
        queryset=Employee.objects.all(), source="employee", write_only=True
    )

    class Meta:
        model = PaymentProfile
        fields = [
            "id",
            "employee",
            "employee_id",
            "base_salary",
            "overtime_payment",
            "last_updated",
        ]


class AttendanceSerializer(serializers.ModelSerializer):
    employee = EmployeeSerializer(read_only=True)
    employee_id = serializers.PrimaryKeyRelatedField(
        queryset=Employee.objects.all(), source="employee", write_only=True
    )
    hours_worked = serializers.FloatField(read_only=True)
    overtime_hours = serializers.FloatField(read_only=True)

    class Meta:
        model = Attendance
        fields = [
            "id",
            "employee",
            "employee_id",
            "date",
            "check_in",
            "check_out",
            "status",
            "hours_worked",
            "overtime_hours",
        ]

    def validate(self, attrs):
        request = self.context["request"]
        user = request.user
        if not hasattr(user, "employee"):
            raise serializers.ValidationError(
                "The user is not linked to any employee profile."
            )
        return super().validate(attrs)

    def validate_check_in(self, value):
        if isinstance(value, str):
            parsed = parse_datetime(value)
            if not parsed:
                raise serializers.ValidationError(
                    "Invalid datetime format. Use ISO 8601 format."
                )
            return parsed
        elif isinstance(value, datetime):
            return value
        raise serializers.ValidationError(
         "Invalid datetime format. Use ISO 8601 format."
        )

    def validate_check_out(self, value):
        if isinstance(value, str):
            parsed = parse_datetime(value)
            if not parsed:
                raise serializers.ValidationError(
                    "Invalid datetime format. Use ISO 8601 format."
                )
            return parsed
        elif isinstance(value, datetime):
            return value
        raise serializers.ValidationError(
         "Invalid datetime format. Use ISO 8601 format."
        )


class LeaveRequestSerializer(serializers.ModelSerializer):
    employee = EmployeeSerializer(read_only=True)
    action_by = UserMiniSerializer(read_only=True)
    days = serializers.IntegerField(read_only=True)

    def validate(self, attrs):
        request = self.context["request"]
        user = request.user

        if not hasattr(user, "employee"):
            raise serializers.ValidationError(
                "The user is not linked to any employee profile."
            )

        start = attrs.get("start_date")
        end = attrs.get("end_date")

        if start and end and start > end:
            raise serializers.ValidationError(
                "Start date cannot be greater than end date."
            )

        existing = LeaveRequest.objects.filter(
            employee=user.employee, start_date=start, end_date=end
        ).first()

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
        read_only_fields = [
            "status",
            "created_at",
            "days",
            "employee",
            "action_by",
        ]


class LeaveBalanceSerializer(serializers.ModelSerializer):
    employee = EmployeeSerializer(read_only=True)

    class Meta:
        model = LeaveBalance
        fields = ["id", "employee", "casual", "sick"]


class PayrollPeriodSerializer(serializers.ModelSerializer):
    class Meta:
        model = PayrollPeriod
        fields = ["id", "start", "end", "is_closed"]

    def validate(self, attrs):
        start = attrs.get("start")
        end = attrs.get("end")

        if start is None or end is None:
            raise serializers.ValidationError(
                "Both 'start' and 'end' dates are required."
            )

        if not isinstance(start, date) or not isinstance(end, date):
            raise serializers.ValidationError(
                "'start' and 'end' must be valid date objects (YYYY-MM-DD)."
            )

        if start > end:
            raise serializers.ValidationError(
                "'start' date cannot be later than 'end' date."
            )

        return attrs


class PayrollSerializer(serializers.ModelSerializer):
    employee = EmployeeSerializer(read_only=True)
    employee_id = serializers.PrimaryKeyRelatedField(
        queryset=Employee.objects.all(), source="employee", write_only=True
    )

    class Meta:
        model = Payroll
        fields = [
            "id",
            "employee",
            "employee_id",
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
        ]
        read_only_fields = ["generated_at", "payslip_file"]
