from django.contrib import admin
from .models import (
    Department, CustomUser, Employee, PaymentProfile, Attendance,
    LeaveRequest, LeaveBalance, PayrollPeriod, Payroll
)

@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ("email","role","is_active","is_staff")
    search_fields = ("email",)

@admin.register(Employee)
class EmployeeAdmin(admin.ModelAdmin):
    list_display = ("fullname","designation","user","is_verified","pending_update")
    search_fields = ("fullname","user__email")

@admin.register(PaymentProfile)
class PaymentProfileAdmin(admin.ModelAdmin):
    list_display = ("employee","base_salary","overtime_payment","last_updated")

admin.site.register(Department)
admin.site.register(Attendance)
admin.site.register(LeaveRequest)
admin.site.register(LeaveBalance)
admin.site.register(PayrollPeriod)
admin.site.register(Payroll)
