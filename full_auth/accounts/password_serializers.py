from rest_framework import serializers
from accounts.models import User
from accounts.utils import generate_mail_code, password_requirements_validator
from accounts.constants import get_password_reset_message, EMAIL_SUBJECT
from django.conf import settings
from threading import Thread
from rest_framework.exceptions import ValidationError
from rest_framework.authtoken.models import Token



class PasswordResetStartSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate(self, attrs):
        try:
            self.user = User.objects.get(**attrs)
        except User.DoesNotExist:
            raise serializers.ValidationError({
                "error": f"Invalid {User.USERNAME_FIELD}"
            })

        return attrs
    
    def save(self):
        password_reset_code = generate_mail_code()
        self.user.password_reset_code = password_reset_code
        self.user.save()
        
        email_thread = Thread(
            target=self.user.email_user,
            kwargs={
                "subject": EMAIL_SUBJECT,
                "message": get_password_reset_message(password_reset_code),
                "from_email": settings.EMAIL_HOST_USER,
        })
        email_thread.start()


class PasswordResetSecurityCodeVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password_reset_code = serializers.IntegerField(required=True)
    
    def validate(self, attrs):
        otp = attrs.pop("password_reset_code")
        
        try:
            self.user = User.objects.get(**attrs)
        except User.DoesNotExist:
            raise serializers.ValidationError({
                "error": f"Invalid email"
            })

        if not self.user.password_reset_code == otp:
            raise ValidationError({
                "error": "OTP isn't valid."
            })

        return attrs


    def save(self):
        self.user.password_reset_code = generate_mail_code()
        self.user.save()


class PasswordResetEndSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password1 = serializers.CharField(required=True)
    password2 = serializers.CharField(required=True)

    def validate(self, attrs):
        passwd1 = attrs.get("password1")
        passwd2 = attrs.get("password2")
        
        try:
            self.user = User.objects.get(email=attrs.get("email"))
        except User.DoesNotExist:
            raise serializers.ValidationError({
                "error": f"Invalid email"
            })

        if not passwd1 == passwd2:
            raise serializers.ValidationError({
                "error": f"Passwords aren't matched"
            })

        return attrs
        

    def save(self):
        passwd1 = self.validated_data.get("password1")
        self.user.set_password = passwd1
        self.user.password_reset_code = generate_mail_code()
        self.user.save()
        

class PasswordResetCodeRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate(self, attrs):
        try:
            self.user = User.objects.get(email=attrs.get("email"))
        except User.DoesNotExist:
            raise serializers.ValidationError({
                "error": f"Invalid email"
            })

        return attrs

    def save(self):
        self.user.password_reset_code = generate_mail_code()
        self.user.save()
        email_thread = Thread(
            target=self.user.email_user,
            kwargs={
                "subject": EMAIL_SUBJECT,
                "message": get_password_reset_message(self.user.password_reset_code),
                "from_email": settings.EMAIL_HOST_USER,
        })
        
        email_thread.start()


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    new_confirm_password = serializers.CharField(required=True)

    def validate(self, attrs):
        user = self.context.get("user")
        old_password = attrs.get("old_password")
        new_password = attrs.get("new_password")
        new_confirm_password = attrs.get("new_confirm_password")


        if not user.check_password(old_password):
            raise ValidationError({
                "error": "Original password isn't valid."
            })
    
        if not password_requirements_validator(new_password):
            raise ValidationError({
                "error": "Password doesn't satisfy requirements."
            })

        if not new_password == new_confirm_password:
            raise ValidationError({
                "error": "New passwords aren't matched."
            })

        return attrs
    
    def save(self):
        user = self.context.get("user")
        new_password = self.validated_data.get("new_password")

        user.set_password(new_password)
        user.save()
        auth_token, created = Token.objects.get_or_create(user=user)
        # getting current auth_token of user
        if not created:
            # if user has got the token before (logged-in his account times before), not newly created
            auth_token.delete()  # delete that old auth_token
            auth_token = Token.objects.create(user=user)  # create new auth_token

        return auth_token.key
        