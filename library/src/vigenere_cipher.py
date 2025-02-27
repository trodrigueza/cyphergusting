import string
from collections import Counter
import numpy as np
from typing import Dict
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
    def index_of_coincidence(text: str) -> float:
        """Calcula el índice de coincidencia de un texto dado."""
        n = len(text)
        if n <= 1:
            return 0
        freqs = Counter(text)
        ic = sum(f * (f - 1) for f in freqs.values()) / (n * (n - 1))
        return ic

    @staticmethod
    def estimate_key_length(text: str, max_len: int = 20, target_ic: float = 0.075) -> int:
        """
        Estima la longitud probable de la clave basándose en el índice de coincidencia.
        """
        best_length = 1
        best_diff = float('inf')
        
        for key_len in range(1, min(max_len, len(text)) + 1):
            ics = [VigenereCipher.index_of_coincidence(text[i::key_len]) for i in range(key_len)]
            avg_ic = np.mean(ics)
            diff = abs(avg_ic - target_ic)
            if diff < best_diff:
                best_diff = diff
                best_length = key_len
        return best_length

    @staticmethod
    def chi_squared_for_shift(subtext: str, shift: int, expected: Dict[str, float]) -> float:
        """
        Calcula la estadística chi-cuadrado para un subtexto rotado por 'shift'.
        """
        rotated = ''.join(chr((ord(c) - ord('A') - shift) % 26 + ord('A')) for c in subtext)
        n = len(rotated)
        observed = Counter(rotated)
        chi_sq = 0.0
        for letter in string.ascii_uppercase:
            o = observed.get(letter, 0)
            e = expected.get(letter, 0) * n
            chi_sq += ((o - e) ** 2) / (e + 1e-6)
        return chi_sq

    @staticmethod
    def frequency_expected(lang: str = 'ES') -> Dict[str, float]:
        """
        Retorna las frecuencias esperadas de letras para el idioma dado.
        Por defecto, se usan las frecuencias en español.
        """
        if lang.upper() == 'ES':
            freqs = {
                'A': 12.53, 'B': 1.42, 'C': 4.68, 'D': 5.86, 'E': 13.68, 'F': 0.69,
                'G': 1.01, 'H': 0.70, 'I': 6.25, 'J': 0.44, 'K': 0.02, 'L': 4.97,
                'M': 3.15, 'N': 6.71, 'O': 8.68, 'P': 2.51, 'Q': 0.88, 'R': 6.87,
                'S': 7.98, 'T': 4.63, 'U': 3.93, 'V': 0.90, 'W': 0.01, 'X': 0.22,
                'Y': 0.90, 'Z': 0.52
            }
        else:
            # Frecuencias en inglés como ejemplo
            freqs = {
                'A': 8.12, 'B': 1.49, 'C': 2.71, 'D': 4.32, 'E': 12.02, 'F': 2.30,
                'G': 2.03, 'H': 5.92, 'I': 7.31, 'J': 0.10, 'K': 0.69, 'L': 3.98,
                'M': 2.61, 'N': 6.95, 'O': 7.68, 'P': 1.82, 'Q': 0.11, 'R': 6.02,
                'S': 6.28, 'T': 9.10, 'U': 2.88, 'V': 1.11, 'W': 2.09, 'X': 0.17,
                'Y': 2.11, 'Z': 0.07
            }
        total = sum(freqs.values())
        return {letter: freq/total for letter, freq in freqs.items()}

    @staticmethod
    def analyze_key(text: str, key_len: int, lang: str = 'ES') -> str:
        """
        Determina la clave probable aplicando el análisis chi-cuadrado sobre cada columna.
        """
        expected = VigenereCipher.frequency_expected(lang)
        columns = [''.join(text[i::key_len]) for i in range(key_len)]
        key = ''
        for col in columns:
            chi_values = [VigenereCipher.chi_squared_for_shift(col, shift, expected) for shift in range(26)]
            best_shift = chi_values.index(min(chi_values))
            key += chr(best_shift + ord('A'))
        return key

    @staticmethod
    def attack(ciphertext: str, lang: str = 'ES') -> str:
        """
        Ataque al cifrado Vigenère:
        - Preprocesa el texto para analizar solo letras.
        - Estima la longitud probable de la clave.
        - Realiza análisis de frecuencia para determinar cada letra.
        - Descifra el texto con la clave encontrada.
        """
        # Filtramos solo letras y convertimos a mayúsculas para análisis
        filtered = ''.join(c for c in ciphertext.upper() if c.isalpha())
        if len(filtered) < 20:
            return "El texto es demasiado corto para un análisis robusto."
        
        key_len = VigenereCipher.estimate_key_length(filtered)
        key = VigenereCipher.analyze_key(filtered, key_len, lang)
        plaintext = VigenereCipher.decrypt(ciphertext, key)
        
        return (
            f"Análisis completado:\n"
            f"Longitud probable de la clave: {key_len}\n"
            f"Clave probable: {key}\n"
            f"Texto posiblemente descifrado:\n{plaintext}\n"
            "Nota: Este ataque es probabilístico y depende de la longitud y calidad del texto."
        )


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
