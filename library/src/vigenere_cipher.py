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
        from collections import Counter
        import numpy as np
        
        def get_ic(text):
            """Calcula el índice de coincidencia del texto"""
            n = len(text)
            if n < 2:
                return 0
            freqs = Counter(text)
            ic = sum(f * (f-1) for f in freqs.values()) / (n * (n-1))
            return ic
        
        def find_key_length(text, max_len=20):
            """Encuentra la longitud probable de la clave usando el índice de coincidencia"""
            best_len = 1
            best_ic = 0
            
            for length in range(1, min(max_len + 1, len(text))):
                avg_ic = 0
                # Dividir el texto en length substrings
                for i in range(length):
                    substring = text[i::length]
                    avg_ic += get_ic(substring)
                avg_ic /= length
                
                # El IC más cercano a 0.065 (valor típico en inglés) o 0.075 (español) es probablemente correcto
                if abs(avg_ic - 0.075) < abs(best_ic - 0.075):
                    best_ic = avg_ic
                    best_len = length
            
            return best_len
        
        def freq_analysis(text):
            """Realiza análisis de frecuencia en el texto"""
            # Frecuencias aproximadas de letras en español
            esp_freqs = {
                'A': 12.53, 'B': 1.42, 'C': 4.68, 'D': 5.86, 'E': 13.68, 'F': 0.69,
                'G': 1.01, 'H': 0.70, 'I': 6.25, 'J': 0.44, 'K': 0.02, 'L': 4.97,
                'M': 3.15, 'N': 6.71, 'O': 8.68, 'P': 2.51, 'Q': 0.88, 'R': 6.87,
                'S': 7.98, 'T': 4.63, 'U': 3.93, 'V': 0.90, 'W': 0.01, 'X': 0.22,
                'Y': 0.90, 'Z': 0.52
            }
            
            # Convertir frecuencias a lista ordenada
            esp_order = sorted(esp_freqs.items(), key=lambda x: x[1], reverse=True)
            esp_order = [c for c, _ in esp_order]
            
            # Calcular frecuencias en el texto
            freqs = Counter(text)
            text_order = sorted(freqs.items(), key=lambda x: x[1], reverse=True)
            text_order = [c for c, _ in text_order if c.isalpha()]
            
            # Mapear las letras más frecuentes
            shift = (ord(text_order[0]) - ord(esp_order[0])) % 26
            return shift
        
        def decrypt_with_key(text, key):
            """Descifra el texto usando una clave dada"""
            plaintext = ""
            key_len = len(key)
            for i, c in enumerate(text):
                if c.isalpha():
                    shift = ord(key[i % key_len]) - ord('A')
                    if c.isupper():
                        plaintext += chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
                    else:
                        plaintext += chr((ord(c) - ord('a') - shift) % 26 + ord('a'))
                else:
                    plaintext += c
            return plaintext
        
        # Preparar el texto para el análisis
        text = text.upper()
        text = ''.join(c for c in text if c.isalpha())
        
        if len(text) < 20:
            return "El texto es demasiado corto para realizar un análisis efectivo."
        
        # Encontrar la longitud probable de la clave
        key_length = find_key_length(text)
        
        # Dividir el texto en columnas según la longitud de la clave
        columns = [''.join(text[i::key_length]) for i in range(key_length)]
        
        # Encontrar cada letra de la clave usando análisis de frecuencia
        key = ''
        for col in columns:
            shift = freq_analysis(col)
            key += chr((shift) % 26 + ord('A'))
        
        # Intentar descifrar con la clave encontrada
        possible_plaintext = decrypt_with_key(text, key)
        
        result = f"Análisis completado:\n"
        result += f"Longitud probable de la clave: {key_length}\n"
        result += f"Clave probable: {key}\n"
        result += f"Texto posiblemente descifrado:\n{possible_plaintext}\n"
        result += "\nNota: Este es un ataque probabilístico. La precisión depende de la longitud del texto y otros factores."
        
        return result

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
