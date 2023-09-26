from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def pad(text):
    """Pad the input text to be a multiple of AES block size"""
    block_size = AES.block_size
    return text + (block_size - len(text) % block_size) * chr(block_size - len(text) % block_size)

def encrypt(plain_text, key):
    """Encrypt the provided plaintext using AES encryption"""
    plain_text = pad(plain_text)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_text = cipher.encrypt(plain_text.encode('utf-8'))
    return base64.b64encode(iv + encrypted_text)

def decrypt(encrypted_text, key):
    """Decrypt the provided ciphertext using AES decryption"""
    encrypted_text = base64.b64decode(encrypted_text)
    iv = encrypted_text[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = cipher.decrypt(encrypted_text[AES.block_size:])
    return decrypted_text.rstrip(chr(AES.block_size).encode('utf-8'))

if __name__ == "__main__":
    # Sample usage
    key = get_random_bytes(16)  # 16 bytes key for AES-128
    plaintext = "This is a test message for encryption."
    print("Original text:", plaintext)

    encrypted_text = encrypt(plaintext, key)
    print("Encrypted text:", encrypted_text)

    decrypted_text = decrypt(encrypted_text, key)
    print("Decrypted text:", decrypted_text.decode('utf-8'))









