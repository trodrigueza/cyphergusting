from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from PIL import Image
import os
import io


project_dir = os.path.join(os.path.dirname(__file__))
data_path = os.path.join(project_dir, "img", "clear_image.jpg")
encryption_path = os.path.join(project_dir, "img", "encrypted_image.png")
decryption_path = os.path.join(project_dir, "img", "decrypted_image.png")


# Encrypt Image with AES and save as another image
# Possible modes are 'CBC', 'CFB', 'OFB', 'CTR'

def encrypt_image(image_path, password, output_path, mode='CBC'):
    # Generate a random salt and derive a key from the password
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = kdf.derive(password.encode())

    # Generate a random IV
    iv = os.urandom(16)
    mode_dict = {'CBC': modes.CBC(iv), 'CFB': modes.CFB(iv), 'OFB': modes.OFB(iv), 'CTR': modes.CTR(iv)}
    cipher_mode = mode_dict.get(mode.upper(), modes.CBC(iv))

    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
    encryptor = cipher.encryptor()

    # Read and process image
    with open(image_path, 'rb') as f:
        image_data = f.read()

    # Pad if required
    if mode.upper() in ['CBC', 'CFB']:
        padder = padding.PKCS7(128).padder()
        image_data = padder.update(image_data) + padder.finalize()

    # Encrypt
    ciphertext = encryptor.update(image_data) + encryptor.finalize()

    # Combine salt, IV, and ciphertext into an image
    encrypted_data = salt + iv + ciphertext
    image = Image.frombytes('L', (len(encrypted_data) // 256 + 1, 256), encrypted_data.ljust((len(encrypted_data) // 256 + 1) * 256, b'\0'))
    image.save(output_path, format='PNG')
    return True

# Decrypt Image with AES

def decrypt_image(encrypted_path, password, output_path, mode='CBC'):
    image = Image.open(encrypted_path)
    encrypted_data = image.tobytes().rstrip(b'\0')

    # Extract salt, IV, and ciphertext
    salt, iv, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]

    # Derive key
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = kdf.derive(password.encode())

    mode_dict = {'CBC': modes.CBC(iv), 'CFB': modes.CFB(iv), 'OFB': modes.OFB(iv), 'CTR': modes.CTR(iv)}
    cipher_mode = mode_dict.get(mode.upper(), modes.CBC(iv))

    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt
    image_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding if needed
    if mode.upper() in ['CBC', 'CFB']:
        unpadder = padding.PKCS7(128).unpadder()
        image_data = unpadder.update(image_data) + unpadder.finalize()

    # Save decrypted image
    with open(output_path, 'wb') as f:
        f.write(image_data)
    return True

# Example usage:
encrypt_image(data_path, 'mypassword', encryption_path, mode='OFB')
decrypt_image(encryption_path, 'mypassword', decryption_path, mode='OFB')
