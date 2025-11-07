import random
from django.db import OperationalError, ProgrammingError
from django.db.models.signals import post_save,post_migrate
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from background_task.models import Task
from .tasks import async_generate_payroll, auto_flag_missing_checkout, auto_generate_monthly_payroll, auto_mark_absent_or_leave, delete_expired_otps
from .models import OTP, Department, Employee, LeaveBalance, PaymentProfile,PayrollPeriod
from .utils import send_otp_email
from django.conf import settings
User = get_user_model()

@receiver(post_migrate)
def schedule_background_tasks(sender, **kwargs):
    TASKS = [
            ("hrapplication.tasks.auto_mark_absent_or_leave", auto_mark_absent_or_leave, 86400),
            ("hrapplication.tasks.auto_flag_missing_checkout", auto_flag_missing_checkout, 86400),
            ("hrapplication.tasks.auto_generate_monthly_payroll", auto_generate_monthly_payroll, 86400),
            ("hrapplication.tasks.delete_expired_otps", delete_expired_otps, 3600),
        ]

    try:
        for task_name, task_function, interval in TASKS:
            if not Task.objects.filter(task_name=task_name).exists():
                task_function(repeat=interval)
    except (OperationalError, ProgrammingError):
        pass

@receiver(post_migrate)
def create_departments(sender, **kwargs):
    for dept_name in settings.COMPANY_CONFIG.get("departments", []):
        if isinstance(dept_name, (list, tuple)) and len(dept_name) >= 2:
            Department.objects.get_or_create(name=dept_name[1], defaults={"description": dept_name[0]})

@receiver(post_save, sender=User)
def create_otp_for_inactive_user(sender, instance, created, **kwargs):
    if created and not instance.is_active and instance.role != "hr":
        otp_code = f"{random.randint(100000, 999999)}"
        OTP.objects.create(user=instance, code=otp_code)  
        send_otp_email(instance.email, otp_code)

@receiver(post_save, sender=Employee)            
def create_employee_related_profiles(sender, instance, created, **kwargs):
    if created:
        overtime=settings.COMPANY_CONFIG.get("payment", {}).get("overtime", 500)
        PaymentProfile.objects.get_or_create(
            employee=instance,
            defaults={"base_salary": 0, "overtime_payment": overtime}
        )

        leave_settings = settings.COMPANY_CONFIG.get("leave", {})
        casual_leave = leave_settings.get("casual", 0)
        sick_leave = leave_settings.get("sick", 0)

        LeaveBalance.objects.get_or_create(
            employee=instance,
            defaults={
                "casual": casual_leave,
                "sick": sick_leave
            }
        )

@receiver(post_save, sender=PayrollPeriod)
def trigger_payroll_background_task(sender, instance, created, **kwargs):
    if created:
        task_name = f"generate-payroll-period-{instance.id}"
        if not Task.objects.filter(task_name=task_name).exists():
            async_generate_payroll(instance.id, task_name=task_name)
            print(f"Background payroll task created for period {instance}")
        else:
            print(f"Task already exists for period {instance}")