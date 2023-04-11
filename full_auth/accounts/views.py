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
from threading import Thread
from django.core.mail import EmailMessage
from pyotp import random_base32, TOTP


@method_decorator(ensure_csrf_cookie, name="dispatch")
class GetCSRFToken(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        return Response({"success": "CSRF Cookie set."})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class SocialAccount(APIView):
    permission_classes = (account_permissions.IsNotAuthenticated,)  # only unauthenticated users can access this view

    def post(self, request):
        email = request.data.get("email")
        first_name = request.data.get("first_name")
        last_name = request.data.get("last_name")
        provider = request.data.get("provider")
        profile_picture_url = request.data.get("profile_picture_url")
        provider_user_access_token = request.data.get("social_access_token")
        if email and first_name and last_name and provider and provider_user_access_token:
            if validate_email(email):  # checking if Email satisfies requirements
                if provider == "google":  # if provider name is google
                    google_token_verification_url = f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={provider_user_access_token}"
                    # verifying returned access token from google
                    token_info = get(google_token_verification_url).json()  # requests library, getting result of
                    # token verification
                    if token_info.get("issued_to") == settings.GOOGLE_CLIENT_ID:  # verifying google api client ID
                        new_user_password = make_password(generate_password())  # generating new encrypted strong
                        # random strong password for user
                        user = User.objects.filter(email=email)
                        if user.exists():  # checking if there's a user account of this email
                            user = user[0]
                            if user.mfa:  # if user has mfa enabled, and has TOTP record
                                return Response({"otp": "Verify OTP."})  # frontend will show otp form screen
                        else:  # if there's no user account of that email
                            activation_code = generate_mail_code()
                            password_reset_code = generate_mail_code()
                            user = User.objects.create_user(email=email, username=email, first_name=first_name,
                                                            last_name=last_name, password=new_user_password,
                                                            is_active=True, profile_picture=profile_picture_url,
                                                            activation_code=activation_code, password_reset_code=password_reset_code)
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
            return Response({"args_error": "Request data paramaters are missing (email, first_name, last_name, "
                                           "accessToken, provider, profile_picture_url)"})


@method_decorator(csrf_protect, name="dispatch")
class LoginView(APIView):
    permission_classes = (account_permissions.IsNotAuthenticated,)  # only unauthenticated users can access this view

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        if email and password:
            if validate_email(email):
                user = User.objects.filter(email=email)  # checking email
                if user.exists():
                    user = user[0]
                    if user.check_password(password):  # checking password
                        user = authenticate(username=email, password=password)  # authenticating user (checking
                        # username, # password, # is_active)
                        if user:  # if user is authenticated
                            if user.mfa:  # if user has mfa enabled
                                return Response({"otp": "Verify OTP."})  # frontend will show otp form screen
                            auth_token, created = Token.objects.get_or_create(user=user)
                            return Response({"success": "[+] Login is successfull", "token": auth_token.key})
                        else:
                            return Response({"not_activated": "[-] User hasn't been activated yet."})
                    else:
                        return Response({"password_error": "[-] Password is incorrect."})
                else:
                    return Response({"exist_error": "[-] Email or password is incorrect."})
            else:
                return Response({"email_invalid": "[-] Email doesn't satisfy requirements. example@example.com"})
        else:
            return Response({"error": "[-] Please enter your email and password."})


@method_decorator(csrf_protect, name="dispatch")
class LogoutView(APIView):
    permission_classes = (permissions.IsAuthenticated,)  # only authenticated users can logout

    def post(self, request):
        token, created = Token.objects.get_or_create(user=request.user)  # getting auth_token for current
        # authenticated user
        token.delete()  # deleting token, Frontend must also remove auth_token from cookies
        return Response({"success": "User token is deleted."})


@method_decorator(csrf_protect, name="dispatch")
class SignUpView(APIView):
    permission_classes = (account_permissions.IsNotAuthenticated,)

    def send_email(self, email, activation_code, password_reset_code, mode="reset"):
        subject = "Company_name Account Team"
        message = ""
        if mode == "reset":
            message = f"Please use the following security code to reset your password:" \
                      f"\n\nSecurity Code: {password_reset_code}\n\nThanks,\nThe Company_name account team"
            # email message and subject for resetting password

        elif mode == "activate":
            # mail message and subject for activating account
            message = f"Please use the following security code to activate your account:" \
                      f"\n\nSecurity Code: {activation_code}\n\nThanks,\nThe Company_name account team"

        email_message = EmailMessage(subject, message, settings.EMAIL_HOST_USER, [email])
        # Sending email message to users' email.
        email_message.send()

    def post(self, request):
        email = request.data.get("email")
        password1 = request.data.get("password1")
        password2 = request.data.get("password2")
        print(email, password1, password2)

        if email and password1 and password2:
            if validate_email(email):  # if email satisfies requirements
                if password1 == password1:
                    if password_requirements_validator(password1):  # if password satisfies requirements
                        if User.objects.filter(email=email).exists():  # checking if there's an account of same email
                            return Response({"email_exist": "[-] Email is already exist."})
                        else:
                            username = f"{email.split('@')[0]}{random.randint(1, 1000000000000)}"

                            activation_code = generate_mail_code()
                            reset_code = generate_mail_code()
                            user = User.objects.create_user(username=username, email=email,
                                                            is_active=False, activation_code=activation_code,
                                                            password_reset_code=reset_code)
                            user.set_password(password1)
                            user.save()
                            email_thread = Thread(
                                target=self.send_email,
                                kwargs={
                                    "email": email,
                                    "mode": "activate",
                                    "activation_code": user.activation_code,
                                    "password_reset_code": user.password_reset_code,
                                }
                            )
                            # Using python threads are more faster to deliver emails.
                            # We won't let Django take responsibility to send email which takes time to send.

                            email_thread.start()  # Frontend should shows a message for user to check email address
                            return Response({"success": "[+] User is created successfully."})
                    else:
                        return Response({"password_requirements": "[-] Password doesn't satisfy requirements."})
                else:
                    return Response({"password_not_match": "[-] Passwords are not matched"})
            else:
                return Response({"email_invalid": "[-] Email doesn't satisfy requirements. example@example.com"})
        else:
            return Response({"error": "[-] Please fill all registration input fields."})


@method_decorator(csrf_protect, name="dispatch")
class SendActivationCode(APIView):
    """User can request to send activation code to his email again by button in frontend."""
    permission_classes = (account_permissions.IsNotAuthenticated, )

    def send_email(self, email, activation_code, password_reset_code, mode="reset"):
        subject = "Company_name Account Team"
        message = ""
        if mode == "reset":
            message = f"Please use the following security code to reset your password:" \
                      f"\n\nSecurity Code: {password_reset_code}\n\nThanks,\nThe Company_name account team"
            # email message and subject for resetting password

        elif mode == "activate":
            # mail message and subject for activating account
            message = f"Please use the following security code to activate your account:" \
                      f"\n\nSecurity Code: {activation_code}\n\nThanks,\nThe Company_name account team"

        email_message = EmailMessage(subject, message, settings.EMAIL_HOST_USER, [email])
        # Sending email message to users' email.
        email_message.send()

    def post(self, request):
        email = request.data.get("email")
        if email:
            user = User.objects.filter(email=email)
            if user.exists():
                user = user[0]
                activation_code = generate_mail_code()

                user.activation_code = activation_code
                user.save()
                email_thread = Thread(
                    target=self.send_email,
                    kwargs={
                        "email": email,
                        "mode": "activate",
                        "activation_code": activation_code,
                        "password_reset_code": user.password_reset_code,
                    }
                )
                email_thread.start()
                return Response({"success": "[+] Security code is sent to your email."})
            return Response({"exist_error": "[-] No such account uses this email."})
        return Response({"error": "[-] Email is not sent."})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class ActivateAccount(APIView):
    permission_classes = (account_permissions.IsNotAuthenticated,)

    def post(self, request):
        activation_code = request.data.get("security_code")  # integar
        print(f"Written security code: {activation_code}")
        email = request.data.get("email")
        if activation_code and email:
            user = User.objects.filter(email=email)
            if user.exists():  # checking DB if there's an account with this id
                user = user[0]
                print(f"DB security code: {user.activation_code}")
                if activation_code == user.activation_code:
                    user.is_active = True  # activate user account
                    user.activation_code = generate_mail_code()
                    user.save()  # saving changed user data to DB
                    auth_token, created = Token.objects.get_or_create(user=user)
                    return Response({"success": "[+] Account is activated successfully.", "token": auth_token.key})
                else:
                    return Response({"code_incorrect": "[-] Security Code is incorrect."})
            else:
                return Response({"exist_error": "[-] Email is incorrect."})
        else:
            return Response({"args_error": "[-] User email and security code aren't provided."})


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
        otp = request.data.get("otp")  # integar
        if otp:
            user = request.user
            if user.mfa:
                user_totp = Totp.objects.filter(user=user)  # getting TOTP data of that user
                if user_totp.exists():
                    user_totp = user_totp[0]
                    totp = TOTP(user_totp.secret, interval=user_totp.interval)  # TOTP object of user secret_key
                    otp_ok = totp.verify(otp)  # verifying OTP depending on TOTP secret_key
                    if otp_ok:  # if otp is valid
                        user.mfa = False  # disable it
                        user.save()  # save changed data to DB
                        user_totp.delete()  # delete it
                        return Response({"success": "User MFA is disabled successfully"})
                    else:
                        return Response({"otp_error": "OTP is invalid."})
                else:
                    return Response({"incomplete_mfa_enable": "[-] User hasn't enabled MFA completely."})
            else:
                return Response({"mfa_disabled": "[-] MFA is already disabled.."})
        else:
            return Response({"otp_missing": "[-] OTP is not sent."})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class GetProvisionURI(APIView):
    """Generating URL for Google Authenticator to scan through QRCode"""
    permission_classes = (permissions.IsAuthenticated,)  # only authenticated users can access this view

    def post(self, request):
        user = request.user
        if user.mfa:  # if user has MFA enabled
            user_totp = Totp.objects.filter(user=user)  # get OTP (Time-based) config data for user
            if user_totp.exists():
                user_totp = user_totp[0]
                provision_uri = build_uri(secret=user_totp.secret, issuer=user_totp.issuer_name, name=user_totp.name)
                # building url for google authetnicator that includes secret_key, name of website, email address of user
                return Response({"provision_uri": provision_uri})
            else:
                return Response({"incomplete_mfa_enable": "[-] User hasn't enabled MFA completely."})
        else:
            return Response({"mfa_disabled": "User hasn't enabled MFA yet."})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class CheckOTP(APIView):
    """Checking OTP View used when Login"""
    permission_classes = (permissions.AllowAny,)  # any user can access this view

    def post(self, request):
        otp = request.data.get("otp")
        email = request.data.get("email")
        if otp and email:
            if validate_email(email):
                user = User.objects.filter(email=email)
                if user.exists():  # checking if there's a user account has this email in DB
                    user = user[0]
                    if user.mfa:
                        user_totp = Totp.objects.filter(user=user)  # getting TOTP data of that user
                        if user_totp.exists():
                            user_totp = user_totp[0]
                            totp = TOTP(user_totp.secret, interval=user_totp.interval)  # TOTP object of user secret_key
                            otp_ok = totp.verify(otp)  # verifying OTP depending on TOTP secret_key
                            if otp_ok:  # if otp is valid
                                auth_token, created = Token.objects.get_or_create(
                                    user=user)  # Getting or creating token for user
                                return Response({"token": auth_token.key})  # returning token if otp is valid
                            else:
                                return Response({"otp_error": "OTP is invalid."})  # if otp is invalid
                        else:
                            return Response({"incomplete_mfa_enable": "[-] User hasn't enabled MFA completely."})
                    else:
                        return Response({"mfa_disabled": "User hasn't MFA enabled."})
                else:
                    return Response({"exist_error": "Account isn't exist"})
            else:
                return Response({"email_invalid": "Email doesn't satisfy requirements. example@example.com"})
        else:
            return Response({"error": "No OTP or Email is recieved."})