from requests import get
from pyotp import random_base32, TOTP
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework.views import APIView, Response
from rest_framework import permissions
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.utils.decorators import method_decorator
from accounts.models import User, TOTP
from accounts.passwords import send_email
from threading import Thread
from accounts.utils import password_requirements_validator, validate_email, generate_password, build_uri
from rest_framework.authtoken.models import Token
from django.conf import settings
from accounts import account_permissions
from accounts.utils import AccountActivationTokenGenerator


@method_decorator(ensure_csrf_cookie, name="dispatch")
class GetCSRFToken(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        return Response({"success": "CSRF Cookie set."})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class SocialAccount(APIView):
    permission_classes = (account_permissions.IsNotAuthenticated,)  # only unauthenticated users can access this view

    def post(self, request):
        email = request.data.get("email", "")  # getting email from request json data
        first_name = request.data.get("first_name", "")  # getting first_name from request json data
        last_name = request.data.get("last_name", "")  # getting last_name from request json data
        # profile_picture_url = request.data.get("profile_picture_url", "")
        provider = request.data.get("provider", "")  # getting provider name from request json data
        provider_user_access_token = request.data.get("social_access_token", "")  # getting social_access_token
        if email and first_name and last_name and provider and provider_user_access_token:  # if their length > 0 and not None
            if validate_email(email):  # checking if Email satisfies requirements
                if provider == "google":  # if provider name is google
                    google_token_verification_url = f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={provider_user_access_token}"
                    # verifying returned access token from google
                    token_info = get(google_token_verification_url).json()  # requests library, getting result of token verification
                    if token_info.get("issued_to", "") == settings.GOOGLE_CLIENT_ID:  # verifying google api client ID
                        new_user_password = make_password(generate_password())  # generating new encrypted strong random password for user
                        user = User.objects.filter(email=email)  # get user from db by email
                        if user.exists():  # checking if there's a user account of this email
                            user = user[0]
                            if user.mfa:  # if user has mfa enabled, and has TOTP record
                                return Response({"otp": "Verify OTP."})  # frontend will show otp form screen
                        else:  # if there's no user account of that email
                            user = User.objects.create_user(email=email, username=email, first_name=first_name,
                                                            last_name=last_name, password=new_user_password,
                                                            is_active=True)
                            # creating new account for user

                        auth_token, created = Token.objects.get_or_create(user=user)
                        # return token only for new created user, or user that has mfa disabled.
                        return Response({"token": auth_token.key})
                    else:
                        return Response({"client_invalid": "Invalid google client id."})
                else:
                    return Response({"provider": "Provider name isn't provided."})
            else:
                return Response({"email_invalid": "Email doesn't satisfy requirements. ex. example@example.com"})
        else:
            return Response({"args_error": "Request data paramaters are missing (email, first_name, last_name, accessToken, provider)"})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class LoginView(APIView):
    permission_classes = (account_permissions.IsNotAuthenticated,)  # only unauthenticated users can access this view

    def post(self, request):
        email = request.data.get("email", "")  # getting email from request json data
        password = request.data.get("password", "")  # getting password from request json data
        if email and password:  # if their length > 0 and not None
            if validate_email(email):  # checking if Email satisfies requirements
                if User.objects.filter(email=email).exists():  # checking if Email satisfies requirements
                    user = authenticate(username=email, password=password)  # authenticating user (checking username, password)
                    if user:  # if user is authenticated
                        if user.mfa:  # if user has mfa enabled
                            return Response({"otp": "Verify OTP."})  # frontend will show otp form screen

                        auth_token, created = Token.objects.get_or_create(user=user)
                        # Getting or creating auth_token for user that has mfa disabled.
                        return Response({"token": auth_token.key})  # returning
                    else:
                        return Response({"creds_error": "Email or Password is incorrect"})
                else:
                    return Response({"exist_error": "Account is not exist."})
            else:
                return Response({"email_invalid": "Email doesn't satisfy requirements. example@example.com"})
        else:
            return Response({"error": "Email or Password is not recieved"})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class LogoutView(APIView):
    permission_classes = (permissions.IsAuthenticated, )  # only authenticated users can logout

    def post(self, request):
        token, created = Token.objects.get_or_create(user=request.user)  # getting auth_token for current authenticated user
        token.delete()  # deleting token, Frontend must also remove auth_token from cookies
        return Response({"success": "User token is deleted."})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class SignUpView(APIView):
    permission_classes = (account_permissions.IsNotAuthenticated,)  # only unauthenticated users can access this view

    def post(self, request):
        email = request.data.get("email", "")  # getting email from request json data
        password1 = request.data.get("password1", "")  # getting password1 from request json data
        password2 = request.data.get("password2", "")  # getting password2 from request json data
        # first_name = request.data.get("first_name", "")
        # last_name = request.data.get("last_name", "")

        if email and password1 and password2:  # if their length > 0 and not None
            if password1 == password2:  # if both passwords are matched
                if validate_email(email):  # if email satisfies requirements
                    if password_requirements_validator(password1):  # if password satisfies requirements
                        if User.objects.filter(email=email).exists():  # checking if there's an account of same email
                            return Response({"exist": "User already has an account."})
                        else:
                            user = User.objects.create_user(username=email, email=email, password=password1,
                                                            is_active=False)
                            # create new user but not activated
                            email_token = AccountActivationTokenGenerator().make_token(user)
                            # Using password reset tokens for activating
                            encoded_user_id = urlsafe_base64_encode(str(user.id).encode())  # encoding user id
                            email_thread = Thread(target=send_email,
                                                  kwargs={"request": request, "email": email, "user_id": encoded_user_id,
                                                          "email_token": email_token, "mode": "activate"})
                            # Sending url for resetting password to users' email using python threads
                            # python threads are used to deliver emails faster, and return response to user without having to wait
                            # for sending email.
                            email_thread.start()
                            # Frontend should shows a message for user to check email address for account activation link
                            return Response({"success": "User is created successfully."})
                    else:
                        return Response({"password_requirements": "Password doesn't satisfy requirements."})
                else:
                    return Response({"email_invalid": "Email doesn't satisfy requirements. example@example.com"})
            else:
                return Response({"password_error": "Password is not match."})
        else:
            return Response({"error": "Fields is empty, fill them."})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class ActivateAccount(APIView):
    permission_classes = (account_permissions.IsNotActivated,)  # only user accounts that aren't activated

    def get(self, request, user_id, activate_token):  # user_id, activate_token are params in url
        if user_id and activate_token:  # if their length > 0 and not None
            account_activation_token_generator = AccountActivationTokenGenerator()  # creating object for genearting, checking email tokens.
            user_id = urlsafe_base64_decode(user_id).decode()  # decoding user_id param
            user = User.objects.filter(id=user_id)
            if user.exists():  # checking DB if there's an account with this id
                user = user[0]
                if account_activation_token_generator.check_token(user, activate_token):  # checking reset_token (email_token) for that user
                    user.is_active = True  # activate user account
                    user.save()  # saving changed user data to DB
                    return Response({"success": "Account is activated successfully."})
                else:
                    return Response({"token_expired": "Token is invalid or expired."})
            else:
                return Response({"exist_error": "Account isn't exist."})
        else:
            return Response({"args_error": "user_id and activate_token aren't provided."})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class EnableMFATOTP(APIView):
    """Enabling MFA using OTP (Time-based) with Google Authenticator"""
    permission_classes = (permissions.IsAuthenticated, )

    def post(self, request):
        user = request.user
        if not user.mfa:  # Only enable mfa it's disabled
            user.mfa = True  # enabling MFA for user
            user.save()  # saving changed user data to DB
            secret_key = random_base32()  # generting secret_key for generating, checking OTPs
            TOTP.objects.create(user=user, secret=secret_key, issuer_name="Testing App", name=user.email)
            # creating new TOTP configuration for user
            return Response({"success": "MFA is enabled, redirect to QR-code"})

        return Response({"mfa": "MFA is already enabled"})


@method_decorator(csrf_protect, name="dispatch")
class DisableMFATOTP(APIView):
    permission_classes = (permissions.IsAuthenticated, )  # only authenticated users can access this view

    def post(self, request):
        user = request.user
        if user.mfa:  # if user has MFA enabled
            user.mfa = False  # disable it
            user.save()  # save changed data to DB
            user_totp = TOTP.objects.get(user=user)  # get TOTP record
            user_totp.delete()  # delete it
            return Response({"success": "User MFA is disabled successfully"})

        return Response({"mfa_disabled": "User MFA is already disabled"})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class GetProvisionURI(APIView):
    """Generating URL for Google Authenticator to scan through QRCode"""
    permission_classes = (permissions.IsAuthenticated,)  # only authenticated users can access this view

    def post(self, request):
        user = request.user
        if user.mfa:  # if user has MFA enabled
            user_pyotp = TOTP.objects.get(user=user)  # get OTP (Time-based) config data for user
            provision_uri = build_uri(secret=user_pyotp.secret, issuer=user_pyotp.issuer_name, name=user_pyotp.name)
            # building url for google authetnicator that includes secret_key, name of website, email address of user
            return Response({"provision_uri": provision_uri})
        else:
            return Response({"mfa_disabled": "User hasn't enabled MFA yet."})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class CheckOTP(APIView):
    """Checking OTP View used when Login"""
    permission_classes = (permissions.AllowAny, )  # any user can access this view

    def post(self, request):
        otp = request.data.get("user_otp", "")  # getting otp from request json data
        email = request.data.get("email", "")  # getting email from request json data
        if otp and email:  # if their length > 0 and not None
            if validate_email(email):  # checking if email satisfies requirements
                user = User.objects.filter(email=email)
                if user.exists():  # checking if there's a user account has this email in DB
                    user = user[0]
                    if user.mfa:
                        user_totp = TOTP.objects.get(user=user)  # getting TOTP data of that user
                        totp = TOTP(user_totp.secret, interval=user_totp.interval)  # TOTP object of user secret_key
                        otp_ok = totp.verify(otp)  # verifying OTP depending on TOTP secret_key
                        if otp_ok:  # if otp is valid
                            auth_token, created = Token.objects.get_or_create(user=user)  # Getting or creating token for user
                            return Response({"token": auth_token.key})  # returning token if otp is valid
                        else:
                            return Response({"otp_error": "OTP is invalid."})  # if otp is invalid
                    else:
                        return Response({"mfa_disabled": "User hasn't MFA enabled."})
                else:
                    return Response({"exist_error": "Account isn't exist"})
            else:
                return Response({"email_invalid": "Email doesn't satisfy requirements. example@example.com"})
        else:
            return Response({"error": "No OTP or Email is recieved."})  # if no otp is sent

