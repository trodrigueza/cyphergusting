class SubstitutionCipher:
    @staticmethod
    def intToPermutation(k):
        """Convierte un entero k en la k-ésima permutación del alfabeto en orden lexicográfico"""
        # Inicializar el alfabeto
        alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        n = len(alphabet)
        result = []
        
        # Convertir k a base factorial
        factoradic = []
        temp_k = k
        for i in range(1, n + 1):
            factoradic.append(temp_k % i)
            temp_k //= i
        factoradic.reverse()
        
        # Construir la permutación
        for i in range(n):
            pos = factoradic[i]
            result.append(alphabet.pop(pos))
        
        return ''.join(result)

    @staticmethod
    def encrypt(plaintext, key):
        try:
            # Si la clave es un número, convertirlo a permutación
            if key.isdigit():
                key = SubstitutionCipher.intToPermutation(int(key))
            print(key) 
            # Validar que la clave sea una permutación válida del alfabeto
            if len(key) != 26 or not all(c.isalpha() for c in key):
                raise ValueError("Key should be either a number or an alphabet's permutation.")
            
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
        except Exception as e:
            raise ValueError("Error in encrypt method: " + str(e))

    @staticmethod
    def decrypt(ciphertext, key):
        if key.isdigit():
            key = SubstitutionCipher.intToPermutation(int(key))
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
        from collections import Counter
        import re
        
        # Frecuencias aproximadas de letras en español
        SPANISH_FREQS = {
            'A': 12.53, 'B': 1.42, 'C': 4.68, 'D': 5.86, 'E': 13.68, 'F': 0.69,
            'G': 1.01, 'H': 0.70, 'I': 6.25, 'J': 0.44, 'K': 0.02, 'L': 4.97,
            'M': 3.15, 'N': 6.71, 'O': 8.68, 'P': 2.51, 'Q': 0.88, 'R': 6.87,
            'S': 7.98, 'T': 4.63, 'U': 3.93, 'V': 0.90, 'W': 0.01, 'X': 0.22,
            'Y': 0.90, 'Z': 0.52
        }
        
        # Palabras comunes en español de 2 y 3 letras
        COMMON_WORDS = {
            2: ['DE', 'LA', 'EL', 'EN', 'UN', 'ES', 'NO', 'SI', 'ME', 'SE', 'YA', 'TE', 'MI', 'TU'],
            3: ['QUE', 'LOS', 'LAS', 'POR', 'CON', 'DEL', 'SUS', 'MAS', 'HOY', 'HAY', 'VER', 'DOS']
        }
        
        def get_frequency_map(text):
            """Calcula el mapa de frecuencias de letras en el texto"""
            total = sum(1 for c in text if c.isalpha())
            freqs = Counter(c for c in text if c.isalpha())
            return {k: (v/total)*100 for k, v in freqs.items()}
        
        def get_word_patterns(text):
            """Obtiene patrones de palabras del texto"""
            words = re.findall(r'\b[A-Z]+\b', text)
            patterns = {}
            for length in [2, 3]:
                patterns[length] = [w for w in words if len(w) == length]
            return patterns
        
        def initial_mapping_by_frequency(cipher_freqs):
            """Crea un mapeo inicial basado en frecuencias"""
            sorted_cipher = sorted(cipher_freqs.items(), key=lambda x: x[1], reverse=True)
            sorted_plain = sorted(SPANISH_FREQS.items(), key=lambda x: x[1], reverse=True)
            
            mapping = {}
            for (cipher_char, _), (plain_char, _) in zip(sorted_cipher, sorted_plain):
                mapping[cipher_char] = plain_char
            
            return mapping
        
        def refine_mapping_with_patterns(mapping, word_patterns):
            """Refina el mapeo usando patrones de palabras comunes"""
            refined_mapping = mapping.copy()
            
            for length, words in word_patterns.items():
                for word in words:
                    # Intentar mapear palabras cifradas a palabras comunes de la misma longitud
                    for common_word in COMMON_WORDS[length]:
                        match = True
                        temp_mapping = {}
                        
                        for c1, c2 in zip(word, common_word):
                            if c1 in refined_mapping and refined_mapping[c1] != c2:
                                match = False
                                break
                            temp_mapping[c1] = c2
                        
                        if match:
                            refined_mapping.update(temp_mapping)
                            
            return refined_mapping
        
        def apply_mapping(text, mapping):
            """Aplica el mapeo al texto cifrado"""
            result = ""
            for c in text:
                if c.isalpha():
                    if c.isupper():
                        result += mapping.get(c, c)
                    else:
                        result += mapping.get(c.upper(), c).lower()
                else:
                    result += c
            return result
        
        # Preparar el texto para el análisis
        clean_text = ''.join(c.upper() for c in ciphertext if c.isalpha() or c.isspace())
        
        if len(clean_text) < 50:
            return "El texto es demasiado corto para realizar un análisis efectivo."
        
        # Calcular frecuencias en el texto cifrado
        cipher_freqs = get_frequency_map(clean_text)
        
        # Obtener patrones de palabras
        word_patterns = get_word_patterns(clean_text)
        
        # Crear mapeo inicial basado en frecuencias
        initial_mapping = initial_mapping_by_frequency(cipher_freqs)
        
        # Refinar el mapeo usando patrones de palabras
        refined_mapping = refine_mapping_with_patterns(initial_mapping, word_patterns)
        
        # Aplicar el mapeo al texto cifrado
        decrypted_text = apply_mapping(ciphertext, refined_mapping)
        
        # Preparar el resultado
        result = "Análisis del cifrado por sustitución:\n\n"
        result += "Mapeo de letras encontrado:\n"
        for cipher_char, plain_char in sorted(refined_mapping.items()):
            result += f"{cipher_char} -> {plain_char}\n"
        
        result += "\nTexto posiblemente descifrado:\n"
        result += decrypted_text
        
        result += "\n\nNota: Este es un ataque probabilístico basado en análisis de frecuencia "
        result += "y patrones de palabras comunes en español. La precisión depende de la longitud "
        result += "del texto y su similitud con las frecuencias del idioma español."
        
        return result

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
