def caesar_decrypt(ciphertext, shift):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            offset = ord('a') if char.islower() else ord('A')
            plaintext += chr((ord(char) - offset - shift) % 26 + offset)
        else:
            plaintext += char
    return plaintext

ciphertext = "khoor zruog"  # Ejemplo: "hello world" cifrado con shift 3
print("Fuerza bruta sobre César:")
for shift in range(26):
    print(f"Shift {shift}: {caesar_decrypt(ciphertext, shift)}")