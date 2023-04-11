# Django-Full-Auth

- Using Django, Django REST Framework
- Using Token Authentication
- Libraries needed are in requirements.txt, some built-in python libraries are used.
(pip install -r requirements.txt)

----------------
[+] Auth Views (Permissions set):

- Using CSRFTokens.
- Social/Normal Login with require of OTP (MFA using Google Authenticator) if user enabled MFA.
- Registering account with is_active=False
- Account Activation required using 6-digit codes sent to user email.
- Logout (Delete user token from DB)
- Enable/Disable MFA View
- QRCode for MFA Enabling (Google Authenticator OTPs).
- Encryption for MFA secret key that identifies Google Authenticator OTPs.
- Reset Password Views
- Change Password View
-------------------------
[+] Middlewares:

- Customized CsrfMiddlware to accept requests from mobile apps, or maybe Postman, Curl normally + web frontend (main)

-------------------
[+] Utils:

- Password requirements for setting user passwords.
- Email validation using regex.
- 6 digit generator for activation, password reset codes.
- Password Generator.
- Provision Uri builder. (for MFA QRCode)

------------------------
[+] Permissions:

- IsNotAuthenticated, only unauthenticated users can access view like Login, Register, ...

-------------------------------------------------------------
[+] Timezone:

- Availability to choose timezone of django (Africa/Cairo, Asia/Riyadh, ...)
- You can display all django timezones from pytz library. (pytz.all_timezones array)

------------------------------
[+] Django Static and Media:

- Reactjs build static files are included to django static
- Django media is configured.

-------------------------------
[+] Django SMTP:

- SMTP configured to work with Google smtp. (details will be in settings.py)
- Emails are sent through Python Thread. (django.core.email.EmailMessage is used)

-----------------
[+] Frontend Support:

- Reactjs + React Router
- Django Templates
