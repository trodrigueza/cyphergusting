def gcd(a, b):
    a = abs(a)
    b = abs(b)
    while b != 0:
        temp = b
        b = a % b
        a = temp
    return a

class AffineCipher:
    @staticmethod
    def encrypt(plaintext, key):
        a = -1
        b = -1
        a_str = ""
        b_str = ""
        i = 0
        
        # Parse the key
        while i < len(key) and key[i] != ' ':
            if key[i].isdigit():
                a_str += key[i]
                i += 1
            else:
                raise ValueError("Invalid key: `a` and `b` should be integers (Z_26), `a` should be a relative prime of 26.")
        
        i += 1  # Skip the space
        while i < len(key) and key[i] != ' ':
            if key[i].isdigit():
                b_str += key[i]
                i += 1
            else:
                raise ValueError("Invalid key: `a` and `b` should be integers (Z_26), `a` should be a relative prime of 26.")
        
        a = int(a_str) % 26
        b = int(b_str) % 26
        
        if a == -1 or b == -1 or gcd(a, 26) != 1:
            raise ValueError("Invalid key: `a` and `b` should be integers (Z_26), `a` should be a relative prime of 26.")
        
        # Encrypt the plaintext
        ciphertext = ""
        for c in plaintext:
            if c.isalpha():
                if c.islower():
                    ciphertext += chr(((ord(c) - ord('a')) * a + b) % 26 + ord('a'))
                else:
                    ciphertext += chr(((ord(c) - ord('A')) * a + b) % 26 + ord('A'))
            else:
                ciphertext += c
        return ciphertext

    @staticmethod
    def decrypt(ciphertext, key):
        a = -1
        b = -1
        a_str = ""
        b_str = ""
        i = 0
        
        # Parse the key
        while i < len(key) and key[i] != ' ':
            if key[i].isdigit():
                a_str += key[i]
                i += 1
            else:
                raise ValueError("Invalid key: `a` and `b` should be integers (Z_26), `a` should be a relative prime of 26.")
        
        i += 1  # Skip the space
        while i < len(key) and key[i] != ' ':
            if key[i].isdigit():
                b_str += key[i]
                i += 1
            else:
                raise ValueError("Invalid key: `a` and `b` should be integers (Z_26), `a` should be a relative prime of 26.")
        
        a = int(a_str) % 26
        b = int(b_str) % 26
        
        if a == -1 or b == -1 or gcd(a, 26) != 1:
            raise ValueError("Invalid key: `a` and `b` should be integers (Z_26), `a` should be a relative prime of 26.")
        
        # Calculate the modular inverse of a
        inv = {1: 1, 3: 9, 9: 3, 5: 21, 21: 5, 7: 15, 15: 7, 11: 19, 19: 11, 17: 23, 23: 17, 25: 25}
        
        # Decrypt the ciphertext
        plaintext = ""
        for c in ciphertext:
            if c.isalpha():
                if c.islower():
                    plaintext += chr(((inv[a] * (ord(c) - ord('a') - b)) % 26 + 26) % 26 + ord('a'))
                else:
                    plaintext += chr(((inv[a] * (ord(c) - ord('A') - b)) % 26 + 26) % 26 + ord('A'))
            else:
                plaintext += c
        return plaintext

    @staticmethod
    def attack(text):
        print("Not implemented yet.")

# Example usage:
# key = "5 8"
# cipher = AffineCipher()

# plaintext = "Hello World"
# encrypted = cipher.encrypt(plaintext, key)
# print("Encrypted:", encrypted)

# decrypted = cipher.decrypt(encrypted, key)
# print("Decrypted:", decrypted)
