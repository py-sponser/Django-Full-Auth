from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect
from rest_framework import permissions
from rest_framework.views import APIView, Response
from accounts import account_permissions
from accounts.utils import *
from django.conf import settings
from requests import get
from accounts.models import User, Totp
from rest_framework.authtoken.models import Token
from pyotp import random_base32
from accounts.serializer import *
from rest_framework import status
from rest_framework.exceptions import ValidationError
from accounts.utils import normalized_serializer_error
from accounts.constants import *
from rest_framework.parsers import MultiPartParser
 

@method_decorator(ensure_csrf_cookie, name="dispatch")
class GetCSRFToken(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        return Response({"success": "CSRF Cookie set."})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class SocialAccount(APIView):
    permission_classes = (account_permissions.IsNotAuthenticated,)  # only unauthenticated users can access this view
    parser_classes = (MultiPartParser, )

    def post(self, request):
        social_login_serializer = SocialLoginSerializer(data=request.data)
        if social_login_serializer.is_valid():
            token = social_login_serializer.save()
            return Response({"success": "[+] Login is successfull", "token": token})

        serializer_errors = normalized_serializer_error(social_login_serializer.errors)
        return Response(serializer_errors, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(csrf_protect, name="dispatch")
class LoginView(APIView):
    permission_classes = (account_permissions.IsNotAuthenticated,)  # only unauthenticated users can access this view

    def post(self, request):
        login_serializer = LoginSerializer(data=request.data)
        if login_serializer.is_valid():
            token = login_serializer.save()
            return Response({"success": "[+] Login is successfull", "token": token})
        serializer_errors = normalized_serializer_error(login_serializer.errors)
        return Response(serializer_errors, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(csrf_protect, name="dispatch")
class LogoutView(APIView):
    permission_classes = (permissions.IsAuthenticated,)  # only authenticated users can logout

    def post(self, request):
        try:
            token = Token.objects.get(user=request.user)  # getting auth_token for current
        except Token.DoesNotExist:
            raise ValidationError({
                "message": "User is already logged out."
            })
        # authenticated user
        token.delete()  # deleting token, Frontend must also remove auth_token from cookies
        return Response({"success": "User is logged out."})


@method_decorator(csrf_protect, name="dispatch")
class SignUpView(APIView):
    permission_classes = (account_permissions.IsNotAuthenticated,)

    def post(self, request):
        register_serializer = RegisterSerializer(data=request.data)
        if register_serializer.is_valid():
            register_serializer.save()
            return Response({"success": "[+] User is created successfully."})
        
        serializer_errors = normalized_serializer_error(register_serializer.errors)
        return Response(serializer_errors, status=status.HTTP_400_BAD_REQUEST)
        

@method_decorator(csrf_protect, name="dispatch")
class ActivationCodeRequest(APIView):
    """User can request to send activation code to his email again by button in frontend."""
    permission_classes = (account_permissions.IsNotAuthenticated, )

    def post(self, request):
        activation_code_request_serializer = ActivationCodeRequestSerializer(data=request.data)
        if activation_code_request_serializer.is_valid():
            activation_code_request_serializer.save()
            return Response({"success": "[+] Security code is sent to your email."})
        
        serializer_errors = normalized_serializer_error(activation_code_request_serializer.errors)
        return Response(serializer_errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class ActivateAccount(APIView):
    permission_classes = (account_permissions.IsNotAuthenticated,)

    def post(self, request):
        activate_account_serializer = ActivateAccountSerializer(data=request.data)
        if activate_account_serializer.is_valid():
            token = activate_account_serializer.save()
            return Response({"success": "[+] Account is activated successfully.", "token": token})
        
        serializer_errors = normalized_serializer_error(activate_account_serializer.errors)
        return Response(serializer_errors, status=status.HTTP_400_BAD_REQUEST)
        


@method_decorator(csrf_protect, name="dispatch")
class CheckMFA(APIView):
    """Returning MFA Status for settings page"""
    permission_classes = (permissions.IsAuthenticated, )

    def get(self, request):
        return Response(request.user.mfa)


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class EnableMFATOTP(APIView):
    """Enabling MFA using OTP (Time-based) with Google Authenticator"""
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        user = request.user
        if not user.mfa:  # Only enable mfa it's disabled
            user.mfa = True  # enabling MFA for user
            user.save()  # saving changed user data to DB
            secret_key = random_base32()  # generting secret_key for generating, checking OTPs
            Totp.objects.create(user=user,
                                secret=secret_key,
                                issuer_name="Testing App",
                                name=user.email)
            # creating new TOTP configuration for user
            return Response({"success": "MFA is enabled, redirect to QR-code"})

        return Response({"mfa": "MFA is already enabled"})


@method_decorator(csrf_protect, name="dispatch")
class DisableMFATOTP(APIView):
    permission_classes = (permissions.IsAuthenticated,)  # only authenticated users can access this view

    def post(self, request):
        disable_mfa_totp_serializer = DisableMFATOTPSerializer(
            data=request.data, 
            context={"user": request.user}
        )
        if disable_mfa_totp_serializer.is_valid():
            disable_mfa_totp_serializer.save()
            return Response({"success": "User MFA is disabled successfully"})
        
        serializer_errors = normalized_serializer_error(disable_mfa_totp_serializer.errors)
        return Response(serializer_errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class GetProvisionURI(APIView):
    """Generating URL for Google Authenticator to scan through QRCode"""
    permission_classes = (permissions.IsAuthenticated,)  # only authenticated users can access this view

    def post(self, request):
        provision_uri_serializer = QRCodeProvisionURISerializer(context={"user": request.user})
        if provision_uri_serializer.is_valid():
            provision_uri = provision_uri_serializer.save()
            return Response({"provision_uri": provision_uri})
        
        serializer_errors = normalized_serializer_error(provision_uri_serializer.errors)
        return Response(serializer_errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class ValidateTOTPView(APIView):
    """Checking OTP View used when Login"""
    permission_classes = (permissions.AllowAny,)  # any user can access this view

    def post(self, request):
        validate_totp_serializer = ValidateTOTPSerializer(data=request.data)
        if validate_totp_serializer.is_valid():
            token = validate_totp_serializer.save()
            return Response({"token": token})  # returning token if otp is valid

        serializer_errors = normalized_serializer_error(validate_totp_serializer.errors)
        return Response(serializer_errors, status=status.HTTP_400_BAD_REQUEST)
        