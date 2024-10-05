from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# Function to encrypt a message
def encrypt(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

# Function to decrypt a message
def decrypt(iv, ct, key):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

# Example usage
if __name__ == "__main__":
    key = get_random_bytes(16)  # AES key must be either 16, 24, or 32 bytes long
    message = input("Enter the decrypt message :")

    # Encrypt the message
    iv, ct = encrypt(message, key)
    print(f"IV: {iv}")
    print(f"Ciphertext , encrypted message : {ct}")

    # Decrypt the message
    decrypted_message = decrypt(iv, ct, key)
    print(f"Decrypted message: {decrypted_message}")
