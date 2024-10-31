from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from rest_framework.views import APIView, Response
from accounts import account_permissions
from accounts.models import User
from rest_framework.authtoken.models import Token
from accounts.utils import password_requirements_validator, normalized_serializer_error
from django.conf import settings
from threading import Thread
from accounts.utils import generate_mail_code
from rest_framework import permissions, status
from accounts.password_serializers import *



@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class PasswordResetStart(APIView):
    """Handling email form that is shown for user, sending email to users' email"""
    permission_classes = (account_permissions.IsNotAuthenticated,)

    def post(self, request):
        password_reset_start_serializer = PasswordResetStartSerializer(data=request.data)
        if password_reset_start_serializer.is_valid():
            password_reset_start_serializer.save()
            return Response({"success": "A mail sent to your email address for resetting password."})
        
        serializer_errors = normalized_serializer_error(password_reset_start_serializer.errors)
        return Response(serializer_errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class PasswordResetSecurityCodeVerification(APIView):
    permission_classes = (account_permissions.IsNotAuthenticated,)  # only unauthenticated users can access this view

    def post(self, request):  # user_id, reset_token are params in url,
        """React Router will get url params, show reset password form for user, then send all of them in POST request"""
        passwd_reset_otp_verification = PasswordResetSecurityCodeVerificationSerializer(data=request.data)
        if passwd_reset_otp_verification.is_valid():
            passwd_reset_otp_verification.save()
            return Response({"success": "[+] Security Code is correct."})
        
        serializer_errors = normalized_serializer_error(passwd_reset_otp_verification.errors)
        return Response(serializer_errors, status=status.HTTP_400_BAD_REQUEST)



@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class PasswordResetEnd(APIView):
    permission_classes = (account_permissions.IsNotAuthenticated, )

    def post(self, request):
        password_reset_end_serializer = PasswordResetEndSerializer(data=request.data)
        if password_reset_end_serializer.is_valid():
            password_reset_end_serializer.save()
            return Response({"success": "[+] Password has been reset successfully."})
        
        serializer_errors = normalized_serializer_error(password_reset_end_serializer.errors)
        return Response(serializer_errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class PasswordResetCodeRequest(APIView):
    permission_classes = (account_permissions.IsNotAuthenticated, )

    def post(self, request):
        password_reset_request_serializer = PasswordResetCodeRequestSerializer(data=request.data)
        if password_reset_request_serializer.is_valid():
            password_reset_request_serializer.save()
            return Response({"success": "A new code is sent to your email to reset your password."})

        serializer_errors = normalized_serializer_error(password_reset_request_serializer.errors)
        return Response(serializer_errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class PasswordChange(APIView):
    permission_classes = (permissions.IsAuthenticated,)  # only authenticated users can access this view

    def post(self, request):
        password_change_serializer = PasswordChangeSerializer(data=request.data, context={"user": request.user})
        if password_change_serializer.is_valid():
            token = password_change_serializer.save()
            return Response({"success": "Password is set successfully", "token": token})
        
        serializer_errors = normalized_serializer_error(password_change_serializer.errors)
        return Response(serializer_errors, status=status.HTTP_400_BAD_REQUEST)

