# QRCode Example for Google Authenticator

- It can work with different authenticators.
- Only works after you enable MFA for your account, and login (to use token in frontend for 'Authorization' request header.)

---------------------------------------

- Using React.js as front-end.
  - Frontend only fetches provision url from backend to embed with QRCode which Google Authenticator need to scan.
    - Dummy Example of final provision uri:
      - otpauth://totp/Secure%20App:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=Secure%20App
  - Frontend only shows the QRCode for you to scan with Google Authenticator.
  
---------------------------------------

[+] Try out:
- Scanning QRCode using Google Authenticator.
- Send POST request to VerifyOTP view "http://127.0.0.1:8000/accounts/mfa/verify-otp/"
using Postman or curl with:
  - Headers: {"Content-Type": "application/json", "Authorization": `Token {auth_token}`}
  - Data: {otp: Google Authenticator OTP numbers, email: "email_address"}
  
------------------

[+] After making any changes:
- npm run build
- replace new build/ with any existing build/ inside django project directory (BASE_DIR).
