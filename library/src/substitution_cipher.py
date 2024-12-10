class SubstitutionCipher:
    @staticmethod
    def encrypt(plaintext, key):
        # Validate key
        if len(key) != 26 or not all(c.isalpha() for c in key):
            raise ValueError("Key should be an alphabet's permutation.")
        
        # Create mappings for lowercase and uppercase letters
        key_low = key.lower()
        key_up = key.upper()
        
        low_map = {}
        up_map = {}
        
        # Create mapping for lowercase letters
        for i, c in enumerate(key_low):
            low_map[chr(ord('a') + i)] = c
        
        # Create mapping for uppercase letters
        for i, c in enumerate(key_up):
            up_map[chr(ord('A') + i)] = c
        
        # Encrypt the plaintext
        ciphertext = ""
        for c in plaintext:
            if c.isalpha():
                if c.islower():
                    ciphertext += low_map[c]
                else:
                    ciphertext += up_map[c]
            else:
                ciphertext += c  # Preserve non-alphabetic characters
        
        return ciphertext

    @staticmethod
    def decrypt(ciphertext, key):
        # Validate key
        if len(key) != 26 or not all(c.isalpha() for c in key):
            raise ValueError("Key should be an alphabet's permutation.")
        
        # Create mappings for lowercase and uppercase letters
        key_low = key.lower()
        key_up = key.upper()
        
        inv_low = {}
        inv_up = {}
        
        # Create inverse mapping for lowercase letters
        for i, c in enumerate(key_low):
            inv_low[c] = chr(ord('a') + i)
        
        # Create inverse mapping for uppercase letters
        for i, c in enumerate(key_up):
            inv_up[c] = chr(ord('A') + i)
        
        # Decrypt the ciphertext
        plaintext = ""
        for c in ciphertext:
            if c.isalpha():
                if c.islower():
                    plaintext += inv_low[c]
                else:
                    plaintext += inv_up[c]
            else:
                plaintext += c  # Preserve non-alphabetic characters
        
        return plaintext

    @staticmethod
    def attack(ciphertext):
        print("Not implemented yet.")
        
# Example usage:
# key = "QAZWSXEDCRFVTGBYHNUJMIKOLP"
# cipher = SubstitutionCipher()

# plaintext = "Hello World"
# encrypted = cipher.encrypt(plaintext, key)
# print("Encrypted:", encrypted)

# decrypted = cipher.decrypt(encrypted, key)
# print("Decrypted:", decrypted)

# # Attack function (not implemented)
# cipher.attack(encrypted)
