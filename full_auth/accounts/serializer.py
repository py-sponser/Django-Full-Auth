from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from rest_framework.validators import ValidationError
from rest_framework.authtoken.models import Token
from rest_framework.views import Response
from accounts.models import User
from accounts.utils import password_requirements_validator, generate_mail_code, build_uri, generate_password
from random import randint
from threading import Thread
from accounts.constants import *
from pyotp import TOTP
from requests import get
from django.conf import settings
from django.contrib.auth.hashers import make_password


User = get_user_model()

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)

    def validate(self, attrs):
        passwd = attrs.pop("password")

        try:
            self.user = User.objects.get(**attrs)
        except User.DoesNotExist:
            raise serializers.ValidationError({
                "error": f"Invalid {User.USERNAME_FIELD}"
            })

        if not self.user.check_password(passwd):
            raise ValidationError({
                "error": "Invalid password"
            })

        if not authenticate(username=self.user.email, password=passwd):
            raise ValidationError({
                "error": "Account isn't activated"
            })

        return attrs

    def save(self):
        if self.user.mfa:
            return Response({"otp": "Verify OTP."})  # frontend will show otp form screen

        auth_token, created = Token.objects.get_or_create(user=self.user)
        return auth_token.key


class SocialLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    social_access_token = serializers.CharField(required=True)
    provider = serializers.CharField(required=True)
    profile_picture_url = serializers.FileField(required=False)
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)

    def validate(self, attrs):
        provider = attrs.get("provider")
        social_access_token = attrs.get("social_access_token")

        if provider == "google":
            google_token_verification_url = f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={social_access_token}"
            token_info = get(google_token_verification_url).json()
            if not token_info.get("issued_to") == settings.GOOGLE_CLIENT_ID:
                raise ValidationError({
                    "error": "Provider API client ID isn't valid."
                })
                

        elif provider == "facebook":
            pass
        
        return attrs

    def save(self):
        email = self.validated_data.get("email")
        user = User.objects.filter(email=email).first()
        if not user:
            new_user_password = make_password(generate_password())
            activation_code = generate_mail_code()
            password_reset_code = generate_mail_code()
            user = User.objects.create_user(
                email=email, 
                username=email, 
                is_active=True, 
                activation_code=activation_code, 
                password_reset_code=password_reset_code,
                password=new_user_password,
                # first_name=first_name,
                # last_name=last_name, 
                # profile_picture=profile_picture_url
            )



        if user.mfa:
            return Response({"otp": "Verify OTP."})  # frontend will show otp form screen

        auth_token, created = Token.objects.get_or_create(user=user)
        return auth_token.key

class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password1 = serializers.CharField(required=True)
    password2 = serializers.CharField(required=True)

    def validate(self, attrs):
        passwd1 = attrs.get("password1")
        passwd2 = attrs.get("password2")

        if User.objects.filter(email=attrs.get("email")).exists():
            raise serializers.ValidationError({
                "error": "Email is already registered."
            })

        if not password_requirements_validator(passwd1):
            raise serializers.ValidationError({
                "error": "Password doesn't satisfy requirements."
            })

        if not passwd1 == passwd2:
            raise serializers.ValidationError({
                "error": "Passwords aren't matched."
            })

        return attrs


    def save(self):
        email = self.validated_data.get("email")
        passwd1 = self.validated_data.get("password1")
        username = f"{email.split('@')[0]}{randint(1, 1000000000000)}"

        activation_code = generate_mail_code()
        reset_code = generate_mail_code()

        user = User.objects.create_user(username=username, email=email,
                                is_active=False, activation_code=activation_code,
                                password_reset_code=reset_code)
        user.set_password(passwd1)
        user.save()

        email_thread = Thread(
            target=user.email_user,
            kwargs={
                "subject": EMAIL_SUBJECT,
                "message": get_account_activation_request_message(activation_code),
                "from_email": settings.EMAIL_HOST_USER,
        })
        email_thread.start()

class ActivationCodeRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


    def validate(self, attrs):
        try:
            self.user = User.objects.get(**attrs)
        except User.DoesNotExist:
            raise serializers.ValidationError({
                "error": f"Invalid email."
            })

        return attrs

    def save(self):
        activation_code = generate_mail_code()

        self.user.activation_code = activation_code
        self.user.save()

        email_thread = Thread(
            target=self.user.email_user,
            kwargs={
                "subject": EMAIL_SUBJECT,
                "message": get_account_activation_request_message(activation_code),
                "from_email": settings.EMAIL_HOST_USER,
        })
        email_thread.start()


class ActivateAccountSerializer(serializers.Serializer):
    security_code = serializers.IntegerField(required=True)
    email = serializers.EmailField(required=True)

    def validate(self, attrs):
        try:
            self.user = User.objects.get(**attrs)
        except User.DoesNotExist:
            raise serializers.ValidationError({
                "error": f"Invalid email."
            })

        if not attrs.get("security_code") == self.user.activation_code:
            raise serializers.ValidationError({
                "error": f"Invalid security code."
            })

        return attrs

    def save(self):
        self.user.is_active = True
        self.user.activation_code = generate_mail_code()
        self.user.save()
        auth_token = Token.objects.create(user=self.user)
        return auth_token.key



class DisableMFATOTPSerializer(serializers.Serializer):
    otp = serializers.CharField(required=True)

    def validate(self, attrs):
        user = self.context.get("user")
        if not hasattr(user, "totp"):
            raise ValidationError({
                "error": "TOTP isn't configured while MFA is enabled." 
            })
        
        if not user.mfa:
            raise ValidationError({
                "error": "MFA isn't enabled." 
            })
        
        user_totp = user.totp
        totp = TOTP(user_totp.secret, interval=user_totp.interval)
        if not totp.verify(attrs.get("otp")):
            raise ValidationError({
                "error": "OTP isn't valid." 
            })

        return attrs

    def save(self):
        user = self.context.get("user")
        user.mfa = False
        user.save()
        user.totp.delete()
        

class QRCodeProvisionURISerializer(serializers.Serializer):
    
    def validate(self, attrs):
        user = self.context.get("user")
        user_totp = user.totp
        
        if not user_totp:
            raise ValidationError({
                "error": "TOTP isn't configured while MFA is enabled." 
            })
        
        if not user.mfa:
            raise ValidationError({
                "error": "MFA isn't enabled." 
            })

        return attrs
    
    def save(self):
        user = self.context.get("user")
        user_totp = user.totp
        
        provision_uri = build_uri(secret=user_totp.secret, issuer=user_totp.issuer_name, name=user_totp.name)
        return provision_uri


class ValidateTOTPSerializer(serializers.Serializer):
    otp = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)

    def validate(self, attrs):
        otp = attrs.pop("otp")

        try:
            self.user = User.objects.get(**attrs)
        except User.DoesNotExist:
            raise serializers.ValidationError({
                "error": f"Invalid {User.USERNAME_FIELD}"
            })

        if not self.user.totp:
            raise serializers.ValidationError({
                "error": "TOTP isn't configured while MFA is enabled."
            })
        
        user_totp = self.user.totp
        totp = TOTP(user_totp.secret, interval=user_totp.interval)
        if not totp.verify(otp):
            raise ValidationError({
                "error": "OTP isn't valid." 
            })
            
        return attrs
    
    def save(self):
        auth_token, created = Token.objects.get_or_create(user=self.user)
        return auth_token.key
