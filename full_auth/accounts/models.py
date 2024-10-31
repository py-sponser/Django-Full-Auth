from django.db import models
from django.contrib.auth.models import AbstractUser
# Create your models here.


class User(AbstractUser):
    email = models.EmailField(unique=True)
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]
    mfa = models.BooleanField(default=False, null=True)
    activation_code = models.IntegerField(null=True, blank=True)
    password_reset_code = models.IntegerField(null=True, blank=True)
    social_image_url = models.URLField(null=True)
    profile_picture = models.ImageField(null=True, upload_to="images/users/", blank=True)


class Totp(models.Model):
    user = models.OneToOneField(User, null=True, on_delete=models.CASCADE)
    secret = models.CharField(max_length=50, null=False, blank=False)  # Secret key used to generate OTP and
    # verify by.
    interval = models.IntegerField(default=30, null=True, blank=True)  # Interval that Authenticator takes to
    # regenerate otp.
    digits = models.IntegerField(default=6, null=True, blank=True)  # OTP Digits that Authenticator generates for our
    # app.
    issuer_name = models.CharField(
        null=True,
        blank=True,
        max_length=255,
        # Application Name to show in Google Authenticator
    )
    name = models.CharField(
        null=True,
        blank=True,
        max_length=255,
        # (Username or Email Address) that is shown beside application name in Google Authenticator
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

