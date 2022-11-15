# Django-Full-Auth

- Using Django, Django REST Framework
- Using Token Authentication
- Libraries needed are in requirements.txt, some built-in python libraries are used.
(pip install -r requirements.txt)

----------------
[+] Auth Views (Permissions assigned):

- Get CsrfToken View
- Login with require of MFA (Google Authenticator OTP) if user enabled it.
- Registration with sending activation url to users' email.
- Logout (Delete user token from DB)
- Account Activation View
- Enable MFA View
- Get Provision Url to embed with Front-end QRCode for Google Authenticator to scan.
- Check OTP View (used when login, if user enabled MFA)
- Reset Password Views
- Change Password View
-------------------------
[+] Middlewares:

- Customized CsrfMiddlware to accept requests from mobile apps, or maybe Postman, Curl

-------------------
[+] Utils:

- Password requirements for setting user passwords.
- Custom token generator for activating accounts.
- Email validation using regex.
- Password Generator.
- Provision Uri builder. (for MFA QRCode)

------------------------
[+] Permissions:

- IsNotAuthenticated, only unauthenticated users can access view like Login, Register, ...
- IsNotActivated, only not activated accounts can access this view (Activating account view)

-----------------
[+] Notes:

- Project templates, urls are coded to run with Reactjs.
- Google has disabled google account less secure apps, you will have to find a free smtp server to use.

