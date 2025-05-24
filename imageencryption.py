from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image
import numpy as np
import io

# Function to convert image to byte array
def image_to_bytes(image_path):
    with open(image_path, 'rb') as img_file:
        return img_file.read()

# Function to convert byte array back to image
def bytes_to_image(img_bytes, output_path):
    img = Image.open(io.BytesIO(img_bytes))
    img.save(output_path)

# Function to encrypt image
def encrypt_image(image_path, key, iv):
    img_bytes = image_to_bytes(image_path)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(pad(img_bytes, AES.block_size))
    return cipher.iv + encrypted_bytes  # Prepend IV to the ciphertext

# Function to decrypt image
def decrypt_image(encrypted_bytes, key):
    iv = encrypted_bytes[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes[AES.block_size:]), AES.block_size)
    return decrypted_bytes

# Generate a random 16-byte key and IV
key = get_random_bytes(16)
iv = get_random_bytes(16)

# Encrypt the image
encrypted_data = encrypt_image('input_image.jpg', key, iv)
with open('encrypted_image.enc', 'wb') as enc_file:
    enc_file.write(encrypted_data)

# Decrypt the image
with open('encrypted_image.enc', 'rb') as enc_file:
    encrypted_data = enc_file.read()
decrypted_data = decrypt_image(encrypted_data, key)
bytes_to_image(decrypted_data, 'decrypted_image.jpg')
