from django.urls import path
from accounts import views, password_views

urlpatterns = [
    # Login, Logout, Register, CSRFToken Urls
    path("csrf/get/", views.GetCSRFToken.as_view()),
    path("login/", views.LoginView.as_view()),
    path("logout/", views.LogoutView.as_view()),
    path("register/", views.SignUpView.as_view()),
    path("register/social-account/", views.SocialAccount.as_view()),
    path("activate/", views.ActivateAccount.as_view()),
    path("activate/resend-code/", views.ActivationCodeRequest.as_view()),
    # MFA urls
    path("mfa/check/", views.CheckMFA.as_view()),
    path("mfa/enable/", views.EnableMFATOTP.as_view()),
    path("mfa/disable/", views.DisableMFATOTP.as_view()),
    path("mfa/get-provision-uri/", views.GetProvisionURI.as_view()),
    path("mfa/check-otp/", views.ValidateTOTPView.as_view()),
    # Password Urls
    path("password/reset/start/", password_views.PasswordResetStart.as_view()),
    path("password/reset/resend-code/", password_views.PasswordResetCodeRequest.as_view()),
    path("password/reset/verify-security-code/", password_views.PasswordResetSecurityCodeVerification.as_view()),
    path("password/change/", password_views.PasswordChange.as_view()),
]