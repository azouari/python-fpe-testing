import pyffx
import string

def format_preserving_encrypt(key, plaintext, encrypt_chars=None):
    """
    Perform format-preserving encryption on letters and digits only, leaving spaces and punctuation unchanged.

    Args:
    - key: A secret key used for encryption.
    - plaintext: The string to encrypt.
    - encrypt_chars: The set of characters to encrypt (default: letters and digits).
    
    Returns:
    - The encrypted string, with letters and digits encrypted, while spaces and punctuation remain unchanged.
    """
    # Default set of characters to encrypt includes lowercase/uppercase letters and digits
    if encrypt_chars is None:
        encrypt_chars = string.ascii_letters + string.digits
    
    # Create an FPE cipher for letters and digits
    fpe = pyffx.String(key, encrypt_chars, length=len([c for c in plaintext if c in encrypt_chars]))
    
    # Encrypt only letters and digits, leave others unchanged
    encrypted_text = []
    encryptable_part = ''.join([c for c in plaintext if c in encrypt_chars])
    encrypted_part = fpe.encrypt(encryptable_part)
    
    encrypted_idx = 0
    for char in plaintext:
        if char in encrypt_chars:
            encrypted_text.append(encrypted_part[encrypted_idx])
            encrypted_idx += 1
        else:
            encrypted_text.append(char)
    
    return ''.join(encrypted_text)

def format_preserving_decrypt(key, ciphertext, encrypt_chars=None):
    """
    Perform format-preserving decryption on letters and digits only, leaving spaces and punctuation unchanged.

    Args:
    - key: A secret key used for decryption.
    - ciphertext: The encrypted string to decrypt.
    - encrypt_chars: The set of characters to decrypt (default: letters and digits).
    
    Returns:
    - The decrypted string, with letters and digits decrypted, while spaces and punctuation remain unchanged.
    """
    # Default set of characters to decrypt includes lowercase/uppercase letters and digits
    if encrypt_chars is None:
        encrypt_chars = string.ascii_letters + string.digits
    
    # Create an FPE cipher for letters and digits
    fpe = pyffx.String(key, encrypt_chars, length=len([c for c in ciphertext if c in encrypt_chars]))
    
    # Decrypt only letters and digits, leave others unchanged
    decrypted_text = []
    decryptable_part = ''.join([c for c in ciphertext if c in encrypt_chars])
    decrypted_part = fpe.decrypt(decryptable_part)
    
    decrypted_idx = 0
    for char in ciphertext:
        if char in encrypt_chars:
            decrypted_text.append(decrypted_part[decrypted_idx])
            decrypted_idx += 1
        else:
            decrypted_text.append(char)
    
    return ''.join(decrypted_text)

# Example usage
key = b'my-secret-key-dd-ee'
plaintext = "640-74-3618"

# Encrypt the string (only letters and digits)
encrypted = format_preserving_encrypt(key, plaintext)
print(f"Encrypted: {encrypted}")

# Decrypt the string
decrypted = format_preserving_decrypt(key, encrypted)
print(f"Decrypted: {decrypted}")
