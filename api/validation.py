import re

def username_validator(username):
    if len(username) > 20:
        return "Max length is 20."
    
    if not re.match(r'^[a-zA-Z0-9._]+$', username):
        return "Combination of letters, number, . or _"
    
    return None


def name_validator(name):
    if len(name) > 25:
        return "Max length is 25."

    if not re.match(r'^[A-Za-z\s]+$', name):
        return "Contains only letters and space."
    
    return None


def phone_number_validator(phone_number):
    if not re.match(r'^[6-9]\d{9}$', phone_number):
        return "Invalid phone number"
    
    return None

def email_validator(email):
    if not re.match(r'^[\w\.-]+@[a-zA-Z\d\.-]+\.[a-zA-Z]{2,}$', email):
        return "Invalid email address."
    
    return None


def password_validator(password):
    if len(password) <= 6:
        return "Password at least 6 characters."
    
    if len(password) >= 15:
        return "Password is too long."
    
    return None