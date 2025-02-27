def vigenere_decrypt(ciphertext, key):
    plaintext = ""
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            offset = ord('a') if char.islower() else ord('A')
            shift = ord(key[key_index % len(key)].lower()) - ord('a')
            plaintext += chr((ord(char) - offset - shift) % 26 + offset)
            key_index += 1
        else:
            plaintext += char
    return plaintext

ciphertext = "lxfopvefrnhr"  # Ejemplo conocido
key = "lemon"              # Clave de ejemplo
print("Desencriptado Vigenère con clave conocida:")
print(vigenere_decrypt(ciphertext, key))