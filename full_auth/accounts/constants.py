EMAIL_SUBJECT = "Company_name Account Team"

def get_password_reset_message(code):
    message = f"Please use the following security code to reset your password:" \
            f"\n\nSecurity Code: {code}\n\nThanks,\nThe Company_name account team"

def get_account_activation_request_message(code):
    # mail message and subject for activating account
    message = f"Please use the following security code to activate your account:" \
                f"\n\nSecurity Code: {code}\n\nThanks,\nThe Company_name account team"