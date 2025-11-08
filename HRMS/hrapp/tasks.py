from background_task import background
from django.utils import timezone
from datetime import timedelta
from .models import Employee, Attendance, LeaveRequest, PayrollPeriod, Payroll, OTP
from calendar import monthrange
from datetime import date
from .utils import generate_payroll_for_period
from .services import generate_payslip_docx
from django.db import transaction


@background(schedule=60)
def auto_mark_absent_or_leave():
    today = timezone.localdate()
    yesterday = today - timedelta(days=1)

    for emp in Employee.objects.all():

        if Attendance.objects.filter(employee=emp, date=yesterday).exists():
            continue

        leave_exists = LeaveRequest.objects.filter(
            user=emp.user,
            status="APPROVED",
            start_date__lte=yesterday,
            end_date__gte=yesterday
        ).exists()

        Attendance.objects.create(
            employee=emp,
            date=yesterday,
            status="on_leave" if leave_exists else "absent",
            check_in=None,
            check_out=None
        )

@background(schedule=60)
def auto_flag_missing_checkout():
    today = timezone.localdate() - timedelta(days=1)
    records = Attendance.objects.filter(
        date=today,
        check_in__isnull=False,
        check_out__isnull=True,
    )
    for att in records:
        att.status = "missing_checkout"
        att.save()

@background(schedule=60)
def auto_generate_monthly_payroll():
    today = date.today()
    last_day = monthrange(today.year, today.month)[1]

    if today.day == last_day:
        period, created = PayrollPeriod.objects.get_or_create(
            start=date(today.year, today.month, 1),
            end=today
        )
        if created:
            print("New PayrollPeriod created")
            async_generate_payroll(period.id)
        else:
            print("PayrollPeriod already exists")
            

@background(schedule=10)
def async_generate_payroll(period_id, task_name=None):
    try:
        with transaction.atomic():
            result = generate_payroll_for_period(period_id)
        period = PayrollPeriod.objects.get(id=period_id)
        print(f"{task_name}: Payroll generation completed for PayrollPeriod {period}.")
    except Exception as e:
        print(f"Error generating payroll/payslips for PayrollPeriod {period_id}: {str(e)}")

  
@background(schedule=5)
def generate_payslip_background(payroll_id):
    try:
        payroll = Payroll.objects.get(id=payroll_id)
        generate_payslip_docx(payroll)
    except Exception as e:
        Payroll.objects.filter(id=payroll_id).update(is_generating=False)
        print(f"Payslip generation failed for Payroll ID {payroll_id} – {e}")

@background(schedule=3600)
def delete_expired_otps():
    OTP.objects.filter(is_used=True).delete()
    OTP.objects.filter(expiration_time__lt=timezone.now()).delete()