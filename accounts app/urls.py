from django.urls import path
from accounts import views
from accounts import passwords as password_views

urlpatterns = [
    # Login, Logout, Register CSRFToken Urls
    path("csrf/get/", views.GetCSRFToken.as_view()),
    path("login/", views.LoginView.as_view()),
    path("logout/", views.LogoutView.as_view()),
    path("register/", views.SignUpView.as_view()),
    path("register/social-account/", views.SocialAccount.as_view()),
    path("activate/<str:user_id>/<str:activate_token>/", views.ActivateAccount.as_view()),
    # MFA urls
    path("mfa/enable/", views.EnableMFATOTP.as_view()),
    path("mfa/disable/", views.DisableMFATOTP.as_view()),
    path("mfa/get-provision-uri/", views.GetProvisionURI.as_view()),
    path("mfa/check-otp/", views.CheckOTP.as_view()),
    # Password Urls
    path("reset_password/start/", password_views.ResetPasswordStart.as_view()),
    path("reset_password/<str:user_id>/<str:reset_token>/", password_views.ResetPasswordComplete.as_view()),
    path("change_password/", password_views.ChangePassword.as_view()),
]
