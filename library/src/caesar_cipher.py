class CaesarCipher:
    @staticmethod
    def encrypt(plaintext, key):
        shift = int(key)
        ciphertext = ""
        for c in plaintext:
            if c.isalpha():
                guide = 'a' if c.islower() else 'A'
                ciphertext += chr(((ord(c) - ord(guide) + shift) % 26) + ord(guide))
            else:
                ciphertext += c  # Preserve spaces and other non-alphabetic characters
        return ciphertext

    @staticmethod
    def decrypt(ciphertext, key):
        shift = int(key)
        plaintext = ""
        for c in ciphertext:
            if c.isalpha():
                guide = 'a' if c.islower() else 'A'
                plaintext += chr(((ord(c) - ord(guide) - shift + 26) % 26) + ord(guide))
            else:
                plaintext += c  # Preserve spaces and other non-alphabetic characters
        return plaintext

    @staticmethod
    def attack(ciphertext):
        possible_solutions = []
        for key in range(26):
            psol = CaesarCipher.decrypt(ciphertext, str(key))
            possible_solutions.append(psol)
        return possible_solutions

# Example usage:
# key = "3"
# cipher = CaesarCipher()

# plaintext = "Hello World"
# encrypted = cipher.encrypt(plaintext, key)
# print("Encrypted:", encrypted)

# decrypted = cipher.decrypt(encrypted, key)
# print("Decrypted:", decrypted)

# # Attacking (brute-forcing all possible keys)
# cipher.attack(encrypted)
