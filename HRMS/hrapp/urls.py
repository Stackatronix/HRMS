from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *

router = DefaultRouter()
router.register("departments", DepartmentViewSet, basename="department")
router.register("employees", EmployeeViewSet, basename="employee")
router.register("attendance", AttendanceViewSet, basename="attendance")
router.register("leaves", LeaveRequestViewSet, basename="leave")
router.register("payroll-periods", PayrollPeriodViewSet, basename="payrollperiod")
router.register("payrolls", PayrollViewSet, basename="payroll")
router.register("users", UserManageViewSet, basename="user")
router.register("payment-profiles", PaymentProfileViewSet, basename="paymentprofile")

urlpatterns = [
    path("", include(router.urls)),
    path("auth/signup/", UserSignupView.as_view(), name="signup"),
    path("auth/login/", UserLoginView.as_view(), name="login"),
    path("auth/logout/", UserLogoutView.as_view(), name="logout"),
    path("auth/refresh/", CookieTokenRefreshView.as_view(), name="refresh-token"),
    path("auth/verify-otp/", VerifyOTPView.as_view(), name="verify-otp"),
]
