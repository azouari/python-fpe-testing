import pyffx
import string

def format_preserving_encrypt(key, plaintext, alphabet=None):
    """
    Perform format-preserving encryption on a string, including spaces and punctuation.

    Args:
    - key: A secret key used for encryption.
    - plaintext: The string to encrypt.
    - alphabet: The set of characters the string is composed of (default: lowercase, digits, spaces, and punctuation).
    
    Returns:
    - The encrypted string, with the same format as the input.
    """
    # Default alphabet includes lowercase letters, digits, spaces, and common punctuation
    if alphabet is None:
        alphabet = string.ascii_lowercase + string.digits + string.punctuation + ' '
    
    # Create an FPE cipher with the given key and alphabet
    fpe = pyffx.String(key, alphabet, length=len(plaintext))
    
    # Encrypt the plaintext
    ciphertext = fpe.encrypt(plaintext)
    
    return ciphertext

def format_preserving_decrypt(key, ciphertext, alphabet=None):
    """
    Perform format-preserving decryption on a string, including spaces and punctuation.

    Args:
    - key: A secret key used for decryption.
    - ciphertext: The encrypted string to decrypt.
    - alphabet: The set of characters the string is composed of (default: lowercase, digits, spaces, and punctuation).
    
    Returns:
    - The decrypted string, with the same format as the input.
    """
    # Default alphabet includes lowercase letters, digits, spaces, and common punctuation
    if alphabet is None:
        alphabet = string.ascii_lowercase + string.digits + string.punctuation + ' '
    
    # Create an FPE cipher with the given key and alphabet
    fpe = pyffx.String(key, alphabet, length=len(ciphertext))
    
    # Decrypt the ciphertext
    plaintext = fpe.decrypt(ciphertext)
    
    return plaintext

# Example usage
key = b'my-secret-key'
plaintext = "hello, world! 123"

# Encrypt the string
encrypted = format_preserving_encrypt(key, plaintext)
print(f"Encrypted: {encrypted}")

# Decrypt the string
decrypted = format_preserving_decrypt(key, encrypted)
print(f"Decrypted: {decrypted}")
