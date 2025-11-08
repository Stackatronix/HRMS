from datetime import timedelta, datetime
from decimal import Decimal
from email.policy import default
from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils import timezone

class Department(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"{self.name}"


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email must be provided")
        extra_fields.setdefault("role", "employee")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.is_active = False
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("role", "hr")
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        user = self.create_user(email, password, **extra_fields)
        user.is_active = True
        user.save(update_fields=["is_active"])
        return user


class CustomUser(AbstractUser):
    username = None
    email = models.EmailField(unique=True)
    ROLE_CHOICES = (("hr", "HR"), ("employee", "Employee"))
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="employee")
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    objects = CustomUserManager()

    def __str__(self):
        return self.email


def get_current_date():
    return timezone.now().date()


def get_current_year():
    return timezone.now().year


class Employee(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    fullname = models.CharField(max_length=200)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True)
    designation = models.CharField(max_length=100, null=True, blank=True)
    date_of_joining = models.DateField(default=get_current_date)
    bank_account = models.CharField(max_length=30, null=True, blank=True)
    ifsc_code = models.CharField(max_length=15, null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    pending_update = models.BooleanField(default=False)

    class Meta:
        unique_together = (
            "user",
            "department",
        )

    def __str__(self):
        return f"{self.fullname} - {self.designation}"
def get_default_overtime_payment():
    try:
        return Decimal(settings.COMPANY_CONFIG.get("payment", {}).get("overtime", 500))
    except (AttributeError, KeyError):
        return Decimal("500.00")

class PaymentProfile(models.Model):
    employee = models.OneToOneField(
        Employee, on_delete=models.CASCADE, related_name="payment_profile"
    )
    base_salary = models.DecimalField(max_digits=10, decimal_places=2)
    overtime_payment = models.DecimalField(
        max_digits=7,
        decimal_places=2,
        default=get_default_overtime_payment
    )
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Payment Profile for {self.employee.fullname}"


def default_otp_expiry():
    return timezone.now() + timedelta(minutes=5)


class OTP(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)
    expiration_time = models.DateTimeField(default=default_otp_expiry)

    def __str__(self):
        return f"OTP for {self.user.email} - {'Used' if self.is_used else 'Unused'}"


class Attendance(models.Model):
    STATUS_CHOICES = [
        ("present", "Present"),
        ("absent", "Absent (Unapproved)"),
        ("on_leave", "Approved Leave"),
        ("missing_checkout", "Missing Checkout"),
        ("late", "Late"),
    ]
    
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE)
    date = models.DateField(default=get_current_date)
    check_in = models.DateTimeField(null=True, blank=True)
    check_out = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)

    class Meta:
        unique_together = ("employee", "date")

    @property
    def hours_worked(self):
        if self.check_in and self.check_out:
            delta = self.check_out - self.check_in
            return round(delta.total_seconds() / 3600, 2)
        return 0.0

    @property
    def overtime_hours(self):
        return max(0.0, self.hours_worked - get_work_hours())

class LeaveRequest(models.Model):
    STATUS = [
        ("PENDING", "Pending"),
        ("APPROVED", "Approved"),
        ("REJECTED", "Rejected"),
        ("CANCELLED", "Cancelled"),
    ]
    TYPE = [
        ("CASUAL", "Casual"),
        ("SICK", "Sick"),
        ("UNPAID", "Unpaid"),
        ("OTHER", "Other"),
    ]
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE)
    type = models.CharField(max_length=10, choices=TYPE)
    start_date = models.DateField()
    end_date = models.DateField()
    reason = models.TextField()
    status = models.CharField(max_length=10, choices=STATUS, default="PENDING")
    created_at = models.DateTimeField(auto_now_add=True)
    action_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="approved_leaves",
    )
    is_paid = models.BooleanField(default=True)
    
    class Meta:
        ordering = ["-created_at"]
        unique_together = ("employee", "start_date", "end_date")

    @property
    def days(self):
        return (self.end_date - self.start_date).days + 1


class LeaveBalance(models.Model):
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE)
    year = models.PositiveIntegerField(default=get_current_year)
    casual = models.PositiveIntegerField(default=18)
    sick = models.PositiveIntegerField(default=12)
    class Meta: 
        unique_together = ("employee", "year")

    def __str__(self):
        return f"Leave balance for {self.employee.user.email}"


class PayrollPeriod(models.Model):
    start = models.DateField()
    end = models.DateField()
    is_closed = models.BooleanField(default=False)

    class Meta:
        unique_together = ("start", "end")
        ordering = ["-start"]

    def __str__(self):
        return f"{self.start} to {self.end}"


class Payroll(models.Model):
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE)
    period = models.ForeignKey(PayrollPeriod, on_delete=models.CASCADE)
    gross = models.DecimalField(max_digits=12, decimal_places=2)
    overtime_pay = models.DecimalField(
        max_digits=12, decimal_places=2, default=Decimal("0.00")
    )
    deductions = models.DecimalField(
        max_digits=12, decimal_places=2, default=Decimal("0.00")
    )
    net = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=8, default="INR")
    line_items = models.JSONField(default=dict, blank=True)
    payslip_file = models.FileField(upload_to="payslips/", null=True, blank=True)
    status = models.CharField(
        max_length=12,
        choices=[("DRAFT", "Draft"), ("FINALIZED", "Finalized"), ("PAID", "Paid")],
        default="DRAFT",
    )
    generated_at = models.DateTimeField(auto_now_add=True)
    is_generating = models.BooleanField(default=False)

    class Meta:
        unique_together = ("employee", "period")
        ordering = ["-generated_at"]

def get_work_hours():
    try:
        start_time_str = settings.COMPANY_CONFIG["work_hours"]["start"]
        end_time_str = settings.COMPANY_CONFIG["work_hours"]["end"]

        start_time = datetime.strptime(start_time_str, "%H:%M")
        end_time = datetime.strptime(end_time_str, "%H:%M")

        duration = end_time - start_time
        work_hours = duration.total_seconds() / 3600 

        if work_hours <= 0:
            return 8.0

        return work_hours
    except Exception as e:
        print(f"Error calculating work hours: {e}")
        return 8.0