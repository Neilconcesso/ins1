from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os

# Vigenère Cipher Implementation
def vigenere_encrypt(plaintext, key):
    key = key.lower()
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    plaintext_int = [ord(i) for i in plaintext]
    ciphertext = ''
    for i in range(len(plaintext_int)):
        value = (plaintext_int[i] + key_as_int[i % key_length]) % 256
        ciphertext += chr(value)
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    key = key.lower()
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    ciphertext_int = [ord(i) for i in ciphertext]
    plaintext = ''
    for i in range(len(ciphertext_int)):
        value = (ciphertext_int[i] - key_as_int[i % key_length]) % 256
        plaintext += chr(value)
    return plaintext

# AES Encryption
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv  # IV is 16 bytes
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))

    # Encode IV and ciphertext separately
    iv_encoded = base64.b64encode(iv).decode('utf-8')
    ct_encoded = base64.b64encode(ct_bytes).decode('utf-8')

    return iv_encoded + ":" + ct_encoded  # Separate IV and Ciphertext with ':'

# AES Decryption
def aes_decrypt(enc_data, key):
    iv_encoded, ct_encoded = enc_data.split(":")  # Split IV and ciphertext
    iv = base64.b64decode(iv_encoded)
    ct = base64.b64decode(ct_encoded)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)

    return pt.decode('utf-8')

# Hybrid Encryption
def hybrid_encrypt(plaintext, vigenere_key, aes_key):
    # Step 1: Vigenère Encryption
    vigenere_encrypted = vigenere_encrypt(plaintext, vigenere_key)
    # Step 2: AES Encryption
    aes_encrypted = aes_encrypt(vigenere_encrypted, aes_key)
    return aes_encrypted

# Hybrid Decryption
def hybrid_decrypt(ciphertext, vigenere_key, aes_key):
    # Step 1: AES Decryption
    aes_decrypted = aes_decrypt(ciphertext, aes_key)
    # Step 2: Vigenère Decryption
    vigenere_decrypted = vigenere_decrypt(aes_decrypted, vigenere_key)
    return vigenere_decrypted

# Example Usage
if __name__ == "__main__":
    # Ensure AES key is 16 bytes (128 bits)
    aes_key = os.urandom(16)  # Save this key securely if you want to decrypt later
    vigenere_key = "yourvigenerekey"

    plaintext = "This is a secret message."

    # Encryption
    encrypted_message = hybrid_encrypt(plaintext, vigenere_key, aes_key)
    print(f"Encrypted: {encrypted_message}")

    # Decryption
    decrypted_message = hybrid_decrypt(encrypted_message, vigenere_key, aes_key)
    print(f"Decrypted: {decrypted_message}")