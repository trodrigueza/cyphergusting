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
        from collections import Counter
        
        def gcd(a, b):
            while b:
                a, b = b, a % b
            return a
        
        def modinv(a, m):
            def extended_gcd(a, b):
                if a == 0:
                    return b, 0, 1
                gcd, x1, y1 = extended_gcd(b % a, a)
                x = y1 - (b // a) * x1
                y = x1
                return gcd, x, y
            
            _, x, _ = extended_gcd(a, m)
            return (x % m + m) % m
        
        def score_text(text):
            """Calcula un puntaje de 'naturalidad' del texto basado en frecuencias del español"""
            # Frecuencias aproximadas de letras en español (en porcentaje)
            SPANISH_FREQS = {
                'A': 12.53, 'B': 1.42, 'C': 4.68, 'D': 5.86, 'E': 13.68, 'F': 0.69,
                'G': 1.01, 'H': 0.70, 'I': 6.25, 'J': 0.44, 'K': 0.02, 'L': 4.97,
                'M': 3.15, 'N': 6.71, 'O': 8.68, 'P': 2.51, 'Q': 0.88, 'R': 6.87,
                'S': 7.98, 'T': 4.63, 'U': 3.93, 'V': 0.90, 'W': 0.01, 'X': 0.22,
                'Y': 0.90, 'Z': 0.52
            }
            
            # Calcular frecuencias en el texto
            total = sum(1 for c in text if c.isalpha())
            if total == 0:
                return float('-inf')
                
            freqs = Counter(c for c in text if c.isalpha())
            text_freqs = {k: (v/total)*100 for k, v in freqs.items()}
            
            # Calcular diferencia con las frecuencias esperadas
            score = 0
            for char, freq in text_freqs.items():
                expected = SPANISH_FREQS.get(char.upper(), 0)
                score -= abs(freq - expected)
            
            return score
        
        def try_decrypt(text, a, b):
            """Intenta descifrar el texto con los parámetros dados"""
            try:
                a_inv = modinv(a, 26)
                result = ""
                for c in text:
                    if c.isalpha():
                        # y = ax + b => x = a^(-1)(y - b)
                        if c.isupper():
                            x = (a_inv * (ord(c) - ord('A') - b)) % 26
                            result += chr(x + ord('A'))
                        else:
                            x = (a_inv * (ord(c.upper()) - ord('A') - b)) % 26
                            result += chr(x + ord('a'))
                    else:
                        result += c
                return result
            except:
                return None
        
        # Preparar el texto para el análisis
        if len(text) < 20:
            return "El texto es demasiado corto para realizar un análisis efectivo."
        
        # Lista de posibles valores de 'a' (deben ser coprimos con 26)
        possible_a = [a for a in range(1, 26) if gcd(a, 26) == 1]
        
        best_score = float('-inf')
        best_params = None
        best_decryption = None
        
        # Probar todas las combinaciones posibles de a y b
        result = "Analizando posibles combinaciones de parámetros...\n\n"
        result += "Top 3 posibles descifrados:\n\n"
        
        top_results = []
        
        for a in possible_a:
            for b in range(26):
                decrypted = try_decrypt(text, a, b)
                if decrypted:
                    score = score_text(decrypted)
                    top_results.append((score, a, b, decrypted))
        
        # Ordenar resultados por puntuación
        top_results.sort(reverse=True)
        
        # Mostrar los 3 mejores resultados
        for i, (score, a, b, decrypted) in enumerate(top_results[:3], 1):
            result += f"{i}. Parámetros encontrados: a={a}, b={b}\n"
            result += f"Texto descifrado:\n{decrypted}\n\n"
        
        result += "Nota: Este es un ataque por fuerza bruta que prueba todas las posibles "
        result += "combinaciones de parámetros y selecciona las que producen texto más "
        result += "similar al español basado en frecuencias de letras."
        
        return result

# Example usage:
# key = "5 8"
# cipher = AffineCipher()

# plaintext = "Hello World"
# encrypted = cipher.encrypt(plaintext, key)
# print("Encrypted:", encrypted)

# decrypted = cipher.decrypt(encrypted, key)
# print("Decrypted:", decrypted)
