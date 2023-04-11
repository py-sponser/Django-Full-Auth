import re, random
from urllib.parse import quote, urlencode


def generate_mail_code():
    email_code_str = [str(random.randint(0, 9)) for counter in range(6)]
    email_code = int("".join(email_code_str))
    return email_code


def password_requirements_validator(password):
    """Checking password requirements for validation when registering account"""
    special_symbols = ["!", '$', '@', '#', '%', "^", "&", "*", "(", ")", "-", "=", "+", "_", "/", "<", ">", ":", ","]
    # symbols to use for checking whether a passwor d contain symbols or not.
    status = True  # boolean variable used for checking

    if len(password) < 7:  # password length should be greater than 7
        status = False

    # if len(password) > 15:  # password length should be lower than 15
    #     status = False

    if not any(char.isdigit() for char in password):  # checking each char in the password if there's a number or not
        status = False

    if not any(char.isupper() for char in password):  # checking each char in the password if there's an uppercase
        # letter or not
        status = False

    if not any(char.islower() for char in password):  # checking each char in the password if there's an lowercase
        # letter or not
        status = False

    if not any(char in special_symbols for char in password):  # checking each char in the password if there's a
        # symbol or not
        status = False
    if status:  # if all requirements exist:
        return status  # returning True


def validate_email(email):
    regex = '^[a-z0-9]+[\._]?[ a-z0-9]+[@]\w+[. ]\w{2,3}$'
    if re.search(regex, email):
        return True
    else:
        return False


def generate_password():
    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
               'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
               't', 'u', 'v', 'w', 'x', 'y', 'z']  # lowercase letters
    uppercase_letters = ['A', 'B', 'C',
                         'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
                         'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
                         'X', 'Y', 'Z']  # uppercase letters
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']  # numbers
    symbols = ['!', "@", '#', '$', '%', "^", '&', '(', ')', '*', '+', "-",
               "_", "+", "/", "|", "?", ">", "<", ";", ":"]  # symbols
    lowercase_letters_no = 4
    uppercase_letters_no = 4
    numbers_no = 4
    sym_no = 4

    password = ""  # password variable

    for i in range(1, lowercase_letters_no + 1):
        """appending random lowercase letters depending on how many a user wants"""
        password += random.choice(letters)

    for i in range(1, uppercase_letters_no + 1):
        """appending random uppercase letters depending on how many a user wants"""
        password += random.choice(uppercase_letters)

    for i in range(1, numbers_no + 1):
        """appending random numbers depending on how many a user wants"""
        password += random.choice(numbers)

    for i in range(1, sym_no + 1):
        """appending random symbols depending on how many a user wants"""
        password += random.choice(symbols)

    powerfull_password = "".join(
        random.sample(password, k=len(password)))  # using join method of strings that converts list to a string.
    # what will be converted to string is a sample of the random password but with randomizing indexes
    # which makes it more random. if random password is "password" > after making a randomized sample >
    # "rpsasdow"
    return powerfull_password


def build_uri(secret, name, issuer):
    otp_type = "totp"
    base_uri = "otpauth://{0}/{1}?{2}"

    url_args = {"secret": secret}

    label = quote(name)
    if issuer is not None:
        label = quote(issuer) + ":" + label
        url_args["issuer"] = issuer

    uri = base_uri.format(otp_type, label, urlencode(url_args).replace("+", "%20"))
    return uri
