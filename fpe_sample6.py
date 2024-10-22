from ff3 import FF3Cipher
import string

def format_preserving_encrypt_ff3(key, tweak, plaintext, alphabet_letters=None, alphabet_digits=None):
    """
    Perform format-preserving encryption using FF3 where:
    - Letters are encrypted as letters
    - Digits are encrypted as digits
    - Spaces, punctuation, and other non-alphabetic/non-numeric characters remain unchanged

    Args:
    - key: A 128-bit (16-byte) or 192-bit (24-byte) encryption key.
    - tweak: A 64-bit (8-byte) tweak (like a nonce or IV).
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
    
    # Create FF3 cipher objects for letters and digits
    cipher_letters = FF3Cipher(key, tweak, alphabet=alphabet_letters)
    cipher_digits = FF3Cipher(key, tweak, alphabet=alphabet_digits)
    
    # Separate letters and digits in the input
    letters_part = ''.join([c for c in plaintext if c in alphabet_letters])
    digits_part = ''.join([c for c in plaintext if c in alphabet_digits])
    
    # Encrypt the letters and digits separately
    encrypted_letters = cipher_letters.encrypt(letters_part)
    encrypted_digits = cipher_digits.encrypt(digits_part)
    
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

def format_preserving_decrypt_ff3(key, tweak, ciphertext, alphabet_letters=None, alphabet_digits=None):
    """
    Perform format-preserving decryption using FF3 where:
    - Letters decrypt to letters
    - Digits decrypt to digits
    - Spaces, punctuation, and other non-alphabetic/non-numeric characters remain unchanged

    Args:
    - key: A 128-bit (16-byte) or 192-bit (24-byte) encryption key.
    - tweak: A 64-bit (8-byte) tweak (like a nonce or IV).
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
    
    # Create FF3 cipher objects for letters and digits
    cipher_letters = FF3Cipher(key, tweak, alphabet=alphabet_letters)
    cipher_digits = FF3Cipher(key, tweak, alphabet=alphabet_digits)
    
    # Separate letters and digits in the input
    letters_part = ''.join([c for c in ciphertext if c in alphabet_letters])
    digits_part = ''.join([c for c in ciphertext if c in alphabet_digits])
    
    # Decrypt the letters and digits separately
    decrypted_letters = cipher_letters.decrypt(letters_part)
    decrypted_digits = cipher_digits.decrypt(digits_part)
    
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
key = b'0123456789abcdef0123456789abcdef'  # 32 characters (256 bits key length) for FF3-1
tweak = b'12345678'  # 8-byte tweak

key = "2DE79D232DF5585D68CE47882AE256D6"
tweak = "CBD09280979564"

plaintext = "Hello, World! 12345"

# Encrypt the string (letters encrypted as letters, numbers as numbers)
encrypted = format_preserving_encrypt_ff3(key, tweak, plaintext)
print(f"Encrypted: {encrypted}")

# Decrypt the string
decrypted = format_preserving_decrypt_ff3(key, tweak, encrypted)
print(f"Decrypted: {decrypted}")
