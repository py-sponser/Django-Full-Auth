from django.utils.decorators import method_decorator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views.decorators.csrf import csrf_protect
from rest_framework.views import APIView, Response
from rest_framework import permissions
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from accounts import account_permissions
from accounts.models import User
from rest_framework.authtoken.models import Token
from accounts.utils import password_requirements_validator
from django.core.mail import EmailMessage
from django.conf import settings
from threading import Thread
from django.contrib.sites.shortcuts import get_current_site


def send_email(request, email, user_id, email_token, mode="reset"):
    domain = get_current_site(request).domain  # getting website domain
    message = f"""
        Visit this url to complete your password reset:
        > http://{domain}/accounts/reset_password/{user_id}/{email_token}/
        This link is valid for only one day.
    """
    # email message and subject for resetting password
    subject = f"Reset password of your account"

    if mode == "activate":
        # mail message and subject for activating account
        message = f"""
            Visit this url to activate your account:
            > http://{domain}/accounts/reset_password/{user_id}/{email_token}/
            This link is valid for only one day.
        """
        subject = f"Activate your account"
    print(subject, message, settings.EMAIL_HOST_USER)
    email_message = EmailMessage(subject, message, settings.EMAIL_HOST_USER, [email])
    # Sending email message to users' email.
    email_message.send()


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class ResetPasswordStart(APIView):
    """Handling email form that is shown for user, sending email to users' email"""
    permission_classes = (account_permissions.IsNotAuthenticated,)

    def post(self, request):
        email = request.data.get("email", "")  # getting users' email from request json data
        if email:  # if email length > 0 and not None
            if User.objects.filter(email=email).exists():  # if there's user has this email in DB
                user = User.objects.get(email=email)  # get that user
                password_reset_token_generator = PasswordResetTokenGenerator()  # creating reset token generator, checker
                email_token = password_reset_token_generator.make_token(user)  # creating reset_token specific for that user
                encoded_user_id = urlsafe_base64_encode(str(user.id).encode())  # encoding user id
                email_thread = Thread(target=send_email, kwargs={"request": request, "email": email, "user_id": encoded_user_id,
                                                                 "email_token": email_token})
                # Sending url for resetting password to users' email using python threads
                # python threads are used to deliver emails faster, and return response to user without having to wait
                # for sending email.
                email_thread.start()
                return Response({"success": "A mail sent to your email address for resetting password.")
            else:
                return Response({"exist_error": "Account isn't exist."})
        else:
            return Response({"fields_error": "Email isn't sent in request."})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class ResetPasswordComplete(APIView):
    """Completing reset"""
    permission_classes = (account_permissions.IsNotAuthenticated,)  # only unauthenticated users can access this view

    def post(self, request, user_id, reset_token):  # user_id, reset_token are params in url,
        """Frontend will get url params, show reset password form for user, then send all of them in POST request"""

        if user_id and reset_token:  # if their length > 0 and not None
            password_reset_token_generator = PasswordResetTokenGenerator()  # creating object for genearting, checking email tokens.
            user_id = urlsafe_base64_decode(user_id).decode()  # decoding user_id param
            print(user_id, reset_token)
            if User.objects.filter(id=user_id).exists():  # checking if user is registered with this id in DB.
                new_password = request.data.get("new_password", "")  # getting password from request json data.
                new_confirm_password = request.data.get("new_confirm_password", "")  # getting confirm_password
                if new_password and new_confirm_password:  # if passwords lengths > 0
                    if new_password == new_confirm_password:  # if passwords are matched
                        if password_requirements_validator(new_password):  # checking if password satisfies requirements
                            user = User.objects.get(id=user_id)  # getting user from DB.
                            if password_reset_token_generator.check_token(user, reset_token):  # checking reset_token of the user
                                user.set_password(new_password)  # setting new password for user
                                user.save()  # saving changed data to DB.
                                auth_token, created = Token.objects.get_or_create(user=user)  # getting current user auth_token
                                if not created:  # if user has got the token before (logged-in his account times before), not newly created
                                    auth_token.delete()  # delete that old auth_token
                                    auth_token, created = Token.objects.get_or_create(user=user)  # create new auth_token
                                return Response({"success": "New password is set successfully.", "token": auth_token.key})
                            else:
                                return Response({"reset_expired": "Reset Token is invalid or expired."})
                        else:
                            return Response({"password_requirement": "Password doesn't satisfy requirements."})
                    else:
                        return Response({"password_match": "Passwords aren't matched."})
                else:
                    return Response({"fields_error": "One or more fields are empty."})
            else:
                return Response({"user_id": "User ID is invalid."})
        else:
            return Response({"args_error": "User ID and reset_token aren't provided."})


@method_decorator(csrf_protect, name="dispatch")  # requiring csrf token for this view
class ChangePassword(APIView):
    permission_classes = (permissions.IsAuthenticated,)  # only authenticated users can access this view

    def post(self, request):
        old_password = request.data.get("old_password", "")  # getting old password from request json data
        new_password = request.data.get("new_password", "")  # getting new_password from request json data
        new_confirm_password = request.data.get("new_confirm_password", "")  # getting new_confirm_password
        if old_password and new_password and new_confirm_password:  # if data has length > 0 and not None
            if new_password == new_confirm_password:  # if new password and confirm password are matched
                if password_requirements_validator(new_password):  # checking if password satisfies requirements
                    user = request.user  # user object is already in request while he's authenticated
                    if user.check_password(old_password):  # checking if old_password is correct
                        user.set_password(new_password)  # setting new password for user
                        user.save()  # saving changed data to DB
                        auth_token, created = Token.objects.get_or_create(user=user)  # getting current auth_token of user
                        if not created:  # if user has got the token before (logged-in his account times before), not newly created
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
