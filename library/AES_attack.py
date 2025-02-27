import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def try_key(key_digits, encryption_path):
    """
    Intenta descifrar el archivo cifrado usando la clave (4 dígitos extendida a 16 bytes).
    Retorna los datos descifrados si se detecta la cabecera JPEG; de lo contrario, None.
    """
    # Construir la clave de 16 bytes (4 dígitos + relleno con '0')
    key = key_digits.ljust(16, '0').encode('utf-8')
    
    # Leer el contenido del archivo encriptado
    with open(encryption_path, 'rb') as f:
        data = f.read()
    
    # Extraer IV (primeros 16 bytes) y ciphertext (resto)
    iv = data[:16]
    ciphertext = data[16:]
    
    # Configurar el cifrado AES en modo CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    try:
        # Descifrar y luego remover padding PKCS7
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        # Verificar si el resultado tiene la cabecera de un JPEG (0xFFD8)
        if decrypted_data.startswith(b'\xff\xd8'):
            return decrypted_data
    except Exception:
        # Si ocurre un error (por ejemplo, padding incorrecto), la clave es errónea
        return None
    return None

def brute_force(encryption_path):
    """
    Realiza un ataque de fuerza bruta probando todas las claves posibles (0000 a 9999).
    Retorna la clave encontrada y los datos descifrados, o (None, None) si falla.
    """
    for i in range(10000):
        key_digits = f"{i:04d}"
        print(f"Probando clave: {key_digits}")
        result = try_key(key_digits, encryption_path)
        if result:
            print(f"¡Clave encontrada! La clave es: {key_digits}")
            return key_digits, result
    return None, None

if __name__ == '__main__':
    # Ruta del archivo cifrado (formato: IV (16 bytes) + ciphertext)
    project_dir = os.path.join(os.path.dirname(__file__))
    encryption_path = os.path.join(project_dir, "img", "encryptedCBC_image.png")
    
    # Ejecutar la búsqueda por fuerza bruta
    key_found, decrypted_data = brute_force(encryption_path)
    
    if key_found:
        output_path = os.path.join(project_dir, "img", "attackedCBC_image.png")
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        print(f"Imagen descifrada guardada en: {output_path}")
    else:
        print("No se encontró la clave en el espacio de búsqueda.")
