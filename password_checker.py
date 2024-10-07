import re

def validate_password(password):
    """
    Validates a password based on the following criteria:
    - Length is between 8 and 20 characters.
    - Contains at least one digit.
    - Contains at least one uppercase letter.
    - Contains at least one lowercase letter.
    - Contains at least one special character from the set '!@#$%^&*()-_+='.
    Args:
        password (str): The password string to validate.
    Returns:
        bool: True if the password meets all criteria, False otherwise.
    """
    if len(password) < 8 or len(password) > 20:
        return False
    
    if not any(char.isdigit() for char in password):
        return False
    
    if not any(char.isupper() for char in password):
        return False
    
    if not any(char.islower() for char in password):
        return False
    
    if not any(char in '!@#$%^&*()-_+=' for char in password):
        return False
    
    return True

def validate_password_with_error_messages(password):
    """
    Validates a password based on the following criteria:
    - Must be at least 8 characters long.
    - Must be no more than 20 characters long.
    - Must contain at least one digit.
    - Must contain at least one uppercase letter.
    - Must contain at least one lowercase letter.
    - Must contain at least one special character from '!@#$%^&*()-_+='.
    Parameters:
    password (str): The password string to validate.
    Returns:
    bool: True if the password meets all criteria.
    Raises:
    ValueError: If the password does not meet any of the criteria.
    """
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if len(password) > 20:
        raise ValueError("Password must be no more than 20 characters long.")
    
    if not any(char.isdigit() for char in password):
        raise ValueError("Password must contain at least one digit.")
    
    if not any(char.isupper() for char in password):
        raise ValueError("Password must contain at least one uppercase letter.")
    
    if not any(char.islower() for char in password):
        raise ValueError("Password must contain at least one lowercase letter.")
    
    special_characters = '!@#$%^&*()-_+='
    if not any(char in special_characters for char in password):
        raise ValueError(f"Password must contain at least one special character from '{special_characters}'.")
    
    return True

def validate_password_with_error_messages_regex(password):
    """
    Validates a password based on specific criteria using regular expressions.
    Args:
        password (str): The password string to validate.
    Raises:
        ValueError: If the password does not meet the following criteria:
            - Must be between 8 and 20 characters long.
            - Must contain at least one digit.
            - Must contain at least one uppercase letter.
            - Must contain at least one lowercase letter.
            - Must contain at least one special character from '!@#$%^&*()-_+='.
    Returns:
        bool: True if the password meets all criteria.
    """
    if not re.fullmatch(r'.{8,20}', password):
        raise ValueError("Password must be between 8 and 20 characters long.")
    
    if not re.search(r'\d', password):
        raise ValueError("Password must contain at least one digit.")
    
    if not re.search(r'[A-Z]', password):
        raise ValueError("Password must contain at least one uppercase letter.")
    
    if not re.search(r'[a-z]', password):
        raise ValueError("Password must contain at least one lowercase letter.")
    
    if not re.search(r'[!@#$%^&*()\-_=+]', password):
        raise ValueError("Password must contain at least one special character from '!@#$%^&*()-_+='.")
    
    return True
