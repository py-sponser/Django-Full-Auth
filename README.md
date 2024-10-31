# Django-Full-Auth with React.js for web frontend.

- Using Django, Django REST Framework
- Using Token Authentication
- Libraries needed are in requirements.txt, some built-in python libraries are used.
(pip install -r requirements.txt)

----------------
[+] Views via APIViews and serializers:

- Requiring CSRFTokens.
- Social/Normal Login.
- Registering account.
- Account Activation required using 6-digit codes sent to user email.
- Logout
- Enable/Disable MFA (Google Authenticator)
- Password Reset by 6-digit codes sent to user email.
- Password Change.

-------------------------
[+] Middlewares:

- Customized CsrfMiddlware: Requiring CSRFToken is ignored for mobile apps, curl, and postman.

-------------------
[+] Utils:

- Password requirements for setting user passwords.
- Email validation using regex.
- 6 digit generator for activation, password reset codes.
- Password Generator.
- Provision Uri builder. (for MFA QRCode)
- Normalizing serializer errors to be more cleaner.

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
- Emails are sent via Python threading. (user.email_user is used)

-----------------
[+] Frontend Support:

- Reactjs + React Router
- Django Templates
