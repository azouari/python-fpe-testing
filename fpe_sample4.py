import pyffx
import string

def format_preserving_encrypt(key, plaintext, alphabet_letters=None, alphabet_digits=None):
    """
    Perform format-preserving encryption where:
    - Letters are encrypted as letters
    - Digits are encrypted as digits
    - Spaces, punctuation, and other non-alphabetic/non-numeric characters remain unchanged

    Args:
    - key: A secret key used for encryption.
    - plaintext: The string to encrypt.
    - alphabet_letters: The set of characters for letters encryption (default: all letters).
    - alphabet_digits: The set of characters for digits encryption (default: all digits).
    
    Returns:
    - The encrypted string, preserving format (letters to letters, digits to digits).
    """
    # Default alphabet for letters includes both lowercase and uppercase
    if alphabet_letters is None:
        alphabet_letters = string.ascii_letters  # 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    
    # Default alphabet for digits includes all digits
    if alphabet_digits is None:
        alphabet_digits = string.digits  # '0123456789'
    
    # Separate letters and digits in the input
    print(f'{plaintext=}')
    letters_part = ''.join([c for c in plaintext if c in alphabet_letters])
    print(f'{letters_part=}')
    digits_part = ''.join([c for c in plaintext if c in alphabet_digits])
    print(f'{digits_part=}')
    
    # Create FPE ciphers for letters and digits
    fpe_letters = pyffx.String(key, alphabet_letters, length=len(letters_part))
    fpe_digits = pyffx.String(key, alphabet_digits, length=len(digits_part))
    
    # Encrypt the letters and digits separately
    encrypted_letters = fpe_letters.encrypt(letters_part)
    print(f'{encrypted_letters=}')
    encrypted_digits = fpe_digits.encrypt(digits_part)
    print(f'{encrypted_digits=}')
    
    # Build the final encrypted string
    encrypted_text = []
    letter_idx, digit_idx = 0, 0
    for char in plaintext:
        if char in alphabet_letters:
            encrypted_text.append(encrypted_letters[letter_idx])
            letter_idx += 1
        elif char in alphabet_digits:
            encrypted_text.append(encrypted_digits[digit_idx])
            digit_idx += 1
        else:
            encrypted_text.append(char)  # Keep non-letter/digit characters unchanged
    
    return ''.join(encrypted_text)

def format_preserving_decrypt(key, ciphertext, alphabet_letters=None, alphabet_digits=None):
    """
    Perform format-preserving decryption where:
    - Letters decrypt to letters
    - Digits decrypt to digits
    - Spaces, punctuation, and other non-alphabetic/non-numeric characters remain unchanged

    Args:
    - key: A secret key used for decryption.
    - ciphertext: The encrypted string to decrypt.
    - alphabet_letters: The set of characters for letters decryption (default: all letters).
    - alphabet_digits: The set of characters for digits decryption (default: all digits).
    
    Returns:
    - The decrypted string, preserving format (letters to letters, digits to digits).
    """
    # Default alphabet for letters includes both lowercase and uppercase
    if alphabet_letters is None:
        alphabet_letters = string.ascii_letters
    
    # Default alphabet for digits includes all digits
    if alphabet_digits is None:
        alphabet_digits = string.digits
    
    # Separate letters and digits in the input
    letters_part = ''.join([c for c in ciphertext if c in alphabet_letters])
    digits_part = ''.join([c for c in ciphertext if c in alphabet_digits])
    
    # Create FPE ciphers for letters and digits
    fpe_letters = pyffx.String(key, alphabet_letters, length=len(letters_part))
    fpe_digits = pyffx.String(key, alphabet_digits, length=len(digits_part))
    
    # Decrypt the letters and digits separately
    decrypted_letters = fpe_letters.decrypt(letters_part)
    decrypted_digits = fpe_digits.decrypt(digits_part)
    
    # Build the final decrypted string
    decrypted_text = []
    letter_idx, digit_idx = 0, 0
    for char in ciphertext:
        if char in alphabet_letters:
            decrypted_text.append(decrypted_letters[letter_idx])
            letter_idx += 1
        elif char in alphabet_digits:
            decrypted_text.append(decrypted_digits[digit_idx])
            digit_idx += 1
        else:
            decrypted_text.append(char)  # Keep non-letter/digit characters unchanged
    
    return ''.join(decrypted_text)

# Example usage
key = b'my-secret-key'
plaintext = "this is too much going on what's that 123 main st zip code is 678888"

# Encrypt the string (letters encrypted as letters, numbers as numbers)
encrypted = format_preserving_encrypt(key, plaintext)
print(f"Encrypted: {encrypted}")

# Decrypt the string
decrypted = format_preserving_decrypt(key, encrypted)
print(f"Decrypted: {decrypted}")
