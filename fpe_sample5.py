from ff3 import FF3Cipher

# Define the encryption parameters as hex strings, not byte literals
key = '0123456789abcdef01234567'  # Key must be a hex string (32 characters = 128 bits)
tweak = 'abcdef123456'  # Tweak must be a hex string (14 characters = 56 bits)

# Create an FF3Cipher instance
cipher = FF3Cipher(key, tweak)

def encrypt_ff3(plaintext):
    # Encrypt the plaintext (which should be numeric or alphanumeric)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def decrypt_ff3(ciphertext):
    # Decrypt the ciphertext
    decrypted_text = cipher.decrypt(ciphertext)
    return decrypted_text

# Example usage
plaintext = "1234567890"  # A numeric string
encrypted_text = encrypt_ff3(plaintext)
print(f"Encrypted: {encrypted_text}")

# Decrypt the ciphertext
decrypted_text = decrypt_ff3(encrypted_text)
print(f"Decrypted: {decrypted_text}")
