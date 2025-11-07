from datetime import timedelta
from decimal import Decimal
from django.core.mail import send_mail
from django.conf import settings
from datetime import datetime, time
from django.utils.timezone import get_current_timezone
from .models import Attendance, Employee, LeaveRequest, Payroll, PayrollPeriod, get_work_hours
from django.db import transaction
from datetime import datetime, timedelta

def send_otp_email(email, otp):
    send_mail(
        subject="Verify your account - OTP",
        message=f"Your OTP is {otp}. It expires in 5 minutes.",
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        fail_silently=False,
    )

def _daterange(start, end):
    while start <= end:
        yield start
        start += timedelta(days=1)

def _is_weekday(d):
    return d.weekday() < settings.COMPANY_CONFIG.get("working_days_per_week", 5)

def _workdays(start, end):
    return sum(1 for d in _daterange(start, end) if _is_weekday(d))

@transaction.atomic
def generate_payroll_for_period(period_id, employee_id=None):
    period = PayrollPeriod.objects.select_for_update().get(pk=period_id)
    start, end = period.start, period.end
    total_working_days = Decimal(_workdays(start, end)) or Decimal("1")
    
    payroll_rows = []
    tz = get_current_timezone()

    employees = Employee.objects.all()
    if employee_id:
        employees = employees.filter(id=employee_id)
    for emp in employees:
        payment_profile = getattr(emp, "payment_profile", None)
        base_salary = payment_profile.base_salary if payment_profile else Decimal("0.00")
        overtime_rate = payment_profile.overtime_payment if payment_profile else Decimal("0.00")
        
        attendance_records = Attendance.objects.filter(employee=emp, date__range=(start, end))
        
        total_hours = Decimal("0.00")
        overtime_hours = Decimal("0.00")
        paid_days = Decimal("0")
        unpaid_days = Decimal("0")

        for att in attendance_records:

            if att.status in ["present", "late"]:
                if att.check_in and att.check_out:
                    hours = Decimal((att.check_out - att.check_in).total_seconds()) / Decimal(3600)
                elif att.check_in and att.check_out is None:
                    working_hours = settings.COMPANY_CONFIG.get("working_hours") or {}
                    end_hour = working_hours.get("end", 17)
                    assumed_checkout = datetime.combine(att.date, time(end_hour, 0), tzinfo=tz)
                    hours = Decimal((assumed_checkout - att.check_in).total_seconds()) / Decimal(3600)
                else:
                    hours = Decimal("0.00")

                total_hours += hours
                if hours > get_work_hours():
                    overtime_hours += (hours - get_work_hours())

                paid_days += 1
            
            
            elif att.status == "on_leave":
                paid_days += 1

            
            elif att.status == "absent":
                unpaid_days += 1
        unpaid_leave_days = LeaveRequest.objects.filter(
            employee=emp, status="APPROVED", is_paid=False,
            start_date__lte=end, end_date__gte=start
        )

        unpaid_days += sum((min(lr.end_date, end) - max(lr.start_date, start)).days + 1 for lr in unpaid_leave_days)
        daily_rate = (base_salary / total_working_days).quantize(Decimal("0.01"))
        base_pay = (daily_rate * paid_days).quantize(Decimal("0.01"))
        deduction = (daily_rate * unpaid_days).quantize(Decimal("0.01"))
        overtime_pay = (overtime_hours * overtime_rate).quantize(Decimal("0.01"))
        gross = base_pay + overtime_pay
        net = gross - deduction

        payroll, created = Payroll.objects.update_or_create(
            employee=emp, period=period,
            defaults={
                "gross": gross,
                "overtime_pay": overtime_pay,
                "deductions": deduction,
                "net": net,
                "currency": "INR",
                "line_items": {
                    "daily_rate": str(daily_rate),
                    "paid_days": float(paid_days),
                    "unpaid_days": float(unpaid_days),
                    "overtime_hours": float(overtime_hours),
                    "base_salary": str(base_salary),
                },
                "status": "FINALIZED" if period.is_closed else "DRAFT",
            }
        )
        payroll_rows.append({"employee": emp.fullname, "gross": str(gross), "net": str(net)})

    return {
        "message": "Payroll calculation completed successfully!",
        "period": f"{start} → {end}",
        "result": payroll_rows
    }

    
