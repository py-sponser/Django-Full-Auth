from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from rest_framework.views import APIView, Response
from accounts import account_permissions
from accounts.models import User
from rest_framework.authtoken.models import Token
from accounts.utils import password_requirements_validator
from django.core.mail import EmailMessage
from django.conf import settings
from threading import Thread
from accounts.utils import generate_mail_code
from rest_framework import permissions


def send_email(email, activation_code, password_reset_code, mode="reset"):
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


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class ResetPasswordStart(APIView):
    """Handling email form that is shown for user, sending email to users' email"""
    permission_classes = (account_permissions.IsNotAuthenticated,)

    def post(self, request):
        email = request.data.get("email")
        if email:
            user = User.objects.filter(email=email)
            if user.exists():  # if there's user has this email in DB
                user = user[0]  # get that user
                password_reset_code = generate_mail_code()
                user.password_reset_code = password_reset_code
                user.save()
                email_thread = Thread(
                    target=send_email,
                    kwargs={
                        "email": email,
                        "mode": "reset",
                        "activation_code": user.activation_code,
                        "password_reset_code": password_reset_code,
                    }
                )
                # Sending url for resetting password to users' email using python threads
                # python threads are used to deliver emails faster, and return response to user without having to wait
                # for sending email.
                email_thread.start()
                return Response({"success": "A mail sent to your email address for resetting password."})
            else:
                return Response({"exist_error": "Account isn't exist."})
        else:
            return Response({"fields_error": "Email isn't sent."})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class PasswordResetSecurityCodeVerification(APIView):
    permission_classes = (account_permissions.IsNotAuthenticated,)  # only unauthenticated users can access this view

    def post(self, request):  # user_id, reset_token are params in url,
        """React Router will get url params, show reset password form for user, then send all of them in POST request"""
        email = request.data.get("email")
        password_reset_code = request.data.get("password_reset_code")
        if email and password_reset_code:
            print(password_reset_code)
            user = User.objects.filter(email=email)
            if user.exists():  # checking if user is registered with this id in DB.
                user = user[0]
                if user.password_reset_code == int(password_reset_code):
                    user.password_reset_code = generate_mail_code()
                    user.save()
                    return Response({"success": "[+] Security Code is correct."})
                return Response({"incorrect": "[-] Security Code is incorrect"})
            else:
                return Response({"user_email": "User email is incorrect."})
        else:
            return Response({"args_error": "User email and security code aren't provided."})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class ResetPasswordEnd(APIView):
    permission_classes = (account_permissions.IsNotAuthenticated, )

    def post(self, request):
        email = request.data.get("email")
        password1 = request.data.get("password1")
        password2 = request.data.get("password2")
        if email and password1 and password2:
            user = User.objects.filter(email=email)
            if user.exists():
                user = user[0]
                if password1 == password2:
                    user.set_password(password1)
                    user.password_reset_code = generate_mail_code()
                    user.save()
                    # redirect user to login page.
                    return Response({"success": "[+] Password has been reset successfully."})
                else:
                    return Response({"passwords_not_match": "[-] Passwords aren't matched."})
            else:
                return Response({"account_not_exist": "[-] Account not exist, check your email input."})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class SendResetPasswordCode(APIView):
    permission_classes = (account_permissions.IsNotAuthenticated, )

    def post(self, request):
        email = request.data.get("email")
        if email:
            user = User.objects.filter(email=email)
            if user.exists():
                user = user[0]
                reset_password_code = generate_mail_code()

                user.password_reset_code = reset_password_code
                user.save()
                email_thread = Thread(
                    target=send_email,
                    kwargs={
                        "email": email,
                        "mode": "reset",
                        "activation_code": user.activation_code,
                        "password_reset_code": reset_password_code,
                    }
                )
                email_thread.start()
                return Response({"success": "A new code is sent to your email to reset your password."})
            return Response({"user_email": "User email is incorrect."})
        return Response({"args_error": "User email is not sent."})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class ChangePassword(APIView):
    permission_classes = (permissions.IsAuthenticated,)  # only authenticated users can access this view

    def post(self, request):
        old_password = request.data.get("old_password")  # getting old password from request json data
        new_password = request.data.get("new_password")  # getting new_password from request json data
        new_confirm_password = request.data.get("new_confirm_password")  # getting new_confirm_password
        if old_password and new_password and new_confirm_password:  # if data has length > 0 and not None
            if new_password == new_confirm_password:  # if new password and confirm password are matched
                if password_requirements_validator(new_password):  # checking if password satisfies requirements
                    user = request.user  # user object is already in request while he's authenticated
                    if user.check_password(old_password):  # checking if old_password is correct
                        user.set_password(new_password)  # setting new password for user
                        user.save()  # saving changed data to DB
                        auth_token, created = Token.objects.get_or_create(user=user)
                        # getting current auth_token of user
                        if not created:
                            # if user has got the token before (logged-in his account times before), not newly created
                            auth_token.delete()  # delete that old auth_token
                            auth_token, created = Token.objects.get_or_create(user=user)  # create new auth_token
                        return Response({"success": "Password is set successfully", "token": auth_token.key})
                    else:
                        return Response({"old_password_error": "Old password is incorrect"})
                else:
                    return Response({"password_requirement": "Password doesn't satisfy requirements."})
            else:
                return Response({"match_error": "New password is not matched. (password and confirm password)"})
        else:
            return Response({"fields_error": "One or more field are missing."})
