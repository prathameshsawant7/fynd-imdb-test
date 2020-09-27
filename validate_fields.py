# for regular expressions
import re

# Make a regular expression for validating an Email
regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'


# for validating an Email
def validate_email(email):
    if re.search(regex, email):
        return True
    else:
        return False


def validate_password(password):
    if len(password) < 8:
        return "Make sure your password is at lest 8 letters"
    elif re.search('[0-9]',password) is None:
        return "Make sure your password has a number in it"
    elif re.search('[A-Z]',password) is None:
        return "Make sure your password has a capital letter in it"
    else:
        return "success"
