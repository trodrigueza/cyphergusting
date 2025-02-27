import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def encrypt_image(image_path, key_digits, output_path, mode='CBC'):
    """
    Cifra la imagen leyendo su contenido binario, usando AES con clave de 4 dígitos numéricos.
    Se utiliza el modo CBC, generando un IV aleatorio. La clave se obtiene completando con ceros.
    El archivo resultante contiene el IV concatenado con el ciphertext.
    """
    # Construir la clave de 16 bytes (4 dígitos + relleno de '0')
    key = key_digits.ljust(16, '0').encode('utf-8')
    
    # Generar IV aleatorio
    iv = os.urandom(16)
    
    # Seleccionar el modo de cifrado (solo se implementa CBC en este ejemplo)
    if mode.upper() == 'CBC':
        cipher_mode = modes.CBC(iv)
    else:
        cipher_mode = modes.CBC(iv)
    
    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Leer los datos de la imagen de forma binaria
    with open(image_path, 'rb') as f:
        image_data = f.read()
    
    # Se aplica padding para que los datos sean múltiplos de 16 bytes
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(image_data) + padder.finalize()
    
    # Cifrar los datos
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Guardar el IV concatenado con el ciphertext en el archivo de salida
    with open(output_path, 'wb') as f:
        f.write(iv + ciphertext)
    
    print("Imagen cifrada guardada en:", output_path)

def decrypt_image(encryption_path, key_digits, output_path, mode='CBC'):
    """
    Descifra la imagen leyendo el IV y el ciphertext del archivo encriptado.
    La clave se construye de la misma forma (4 dígitos completados con ceros).
    """
    key = key_digits.ljust(16, '0').encode('utf-8')
    
    # Leer los datos encriptados
    with open(encryption_path, 'rb') as f:
        data = f.read()
    
    # Extraer el IV (primeros 16 bytes) y el ciphertext (resto)
    iv = data[:16]
    ciphertext = data[16:]
    
    if mode.upper() == 'CBC':
        cipher_mode = modes.CBC(iv)
    else:
        cipher_mode = modes.CBC(iv)
    
    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Descifrar y luego quitar el padding
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
    
    # Guardar la imagen descifrada
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)
    
    print("Imagen descifrada guardada en:", output_path)

# Rutas de los archivos
project_dir = os.path.join(os.path.dirname(__file__))
image_path = os.path.join(project_dir, "img", "clear_image.jpg")
encryption_path = os.path.join(project_dir, "img", "encryptedCBC_image.png")
decryption_path = os.path.join(project_dir, "img", "decryptedCBC_image.png")

if __name__ == '__main__':
    # Clave de 4 dígitos (por ejemplo, "1234")
    key_digits = "1234"
    
    # Modo de cifrado (en este ejemplo se usa CBC)
    mode = "CBC"
    
    # Cifrar y descifrar la imagen
    encrypt_image(image_path, key_digits, encryption_path, mode=mode)
    decrypt_image(encryption_path, key_digits, decryption_path, mode=mode)
