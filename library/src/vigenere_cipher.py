class VigenereCipher:
    @staticmethod
    def encrypt(plaintext, key):
        m = len(key)
        n = len(plaintext)
        
        # Validate key
        if not all(c.isalpha() for c in key):
            raise ValueError("Key should consist of alphabetic characters.")
        
        # Validate that the plaintext is not shorter than the key
        if n < m:
            raise ValueError("Plaintext should not be shorter than key.")
        
        # Create lowercase and uppercase versions of the key
        low_key = key.lower()
        up_key = key.upper()
        
        ciphertext = []
        for i in range(n):
            if plaintext[i].isalpha():
                if plaintext[i].islower():
                    ciphertext.append(chr(((ord(plaintext[i]) - ord('a') + ord(low_key[i % m]) - ord('a')) % 26) + ord('a')))
                else:
                    ciphertext.append(chr(((ord(plaintext[i]) - ord('A') + ord(up_key[i % m]) - ord('A')) % 26) + ord('A')))
            else:
                ciphertext.append(plaintext[i])  # Preserve non-alphabetic characters

        return ''.join(ciphertext)

    @staticmethod
    def decrypt(ciphertext, key):
        m = len(key)
        n = len(ciphertext)

        # Validate key
        if not all(c.isalpha() for c in key):
            raise ValueError("Key should consist of alphabetic characters.")
        
        # Validate that the ciphertext is not shorter than the key
        if n < m:
            raise ValueError("Ciphertext should not be shorter than key.")
        
        # Create lowercase and uppercase versions of the key
        low_key = key.lower()
        up_key = key.upper()
        
        plaintext = []
        for i in range(n):
            if ciphertext[i].isalpha():
                if ciphertext[i].islower():
                    plaintext.append(chr(((ord(ciphertext[i]) - ord(low_key[i % m])) % 26 + 26) % 26 + ord('a')))
                else:
                    plaintext.append(chr(((ord(ciphertext[i]) - ord(up_key[i % m])) % 26 + 26) % 26 + ord('A')))
            else:
                plaintext.append(ciphertext[i])  # Preserve non-alphabetic characters

        return ''.join(plaintext)

    @staticmethod
    def attack(text):
        print("Not implemented yet.")
        
# Example usage:
# key = "KEY"
# cipher = VigenereCipher()

# plaintext = "Hello World"
# encrypted = cipher.encrypt(plaintext, key)
# print("Encrypted:", encrypted)

# decrypted = cipher.decrypt(encrypted, key)
# print("Decrypted:", decrypted)

# # Attack function (not implemented)
# cipher.attack(encrypted)
