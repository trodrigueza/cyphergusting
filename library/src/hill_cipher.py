import numpy as np
from sympy import Matrix, mod_inverse
from math import sqrt
from library.src.utilities import toInt, toStr

class HillCipher:
    mod = 26

    #Key Inverse Generation
    @staticmethod
    def InvMatrixModular(matrix):
        auxMatrix = Matrix(matrix)
        detInv = mod_inverse(auxMatrix.det(), HillCipher.mod)
        adjugateMatrix = auxMatrix.adjugate()
        inverseMatrix = (detInv * adjugateMatrix) % HillCipher.mod
        return np.array(inverseMatrix)

    @staticmethod
    def CheckValidKey(plaintext, key:str):
        dim = sqrt(len(key))
        if(dim.is_integer() and dim <= len(plaintext) and len(plaintext) % dim == 0):
            matrix = np.array(list(key))
            matrix = matrix.reshape(int(dim), int(dim))
            matrix = np.vectorize(toInt)(matrix)
            auxMatrix = Matrix(matrix)
            det = auxMatrix.det()
            if(np.gcd(det, HillCipher.mod) == 1):
                return matrix
            else:
                raise ValueError("Key is not modularly invertible")
        else:
            raise ValueError("Key is not a valid square matrix")

    @staticmethod
    def encrypt(plainText, key):
        text = np.vectorize(toInt)(np.array(list(plainText.replace(" ", "").upper())))
        keyM = HillCipher.CheckValidKey(plainText, key)

        sizeText = len(text)
        sizeBlock = len(keyM)

        text = text.reshape(sizeBlock, int(sizeText / sizeBlock))

        cipherText = np.matmul(keyM, text) % HillCipher.mod

        cipherText = np.vectorize(toStr)(cipherText.flatten())
        cipherText = ''.join(map(str, cipherText))

        return cipherText
    
    @staticmethod
    def decrypt(cipherText, key):
        text = np.vectorize(toInt)(np.array(list(cipherText.replace(" ", "").upper())))
        keyM = HillCipher.CheckValidKey(cipherText, key)

        sizeText = len(text)
        sizeBlock = len(keyM)

        text = text.reshape(sizeBlock, int(sizeText / sizeBlock))

        invKey = HillCipher.InvMatrixModular(keyM)

        plainText = np.matmul(invKey, text) % HillCipher.mod

        plainText = np.vectorize(toStr)(plainText.flatten())
        plainText = ''.join(map(str, plainText))

        return plainText
    
    @staticmethod
    def attack(ciphertext, known_plaintext=None):
        import numpy as np
        from sympy import Matrix
        
        def find_possible_key_size(text_length):
            """Encuentra posibles tamaños de clave basados en la longitud del texto"""
            possible_sizes = []
            for i in range(2, 6):  # Probamos matrices de 2x2 hasta 5x5
                if text_length % i == 0:
                    possible_sizes.append(i)
            return possible_sizes
        
        def try_known_plaintext_attack(ciphertext, plaintext, size):
            """Intenta recuperar la clave usando texto claro conocido"""
            # Convertir texto a números
            P = np.array([ord(c) - ord('A') for c in plaintext.upper() if c.isalpha()])
            C = np.array([ord(c) - ord('A') for c in ciphertext.upper() if c.isalpha()])
            
            if len(P) < size * size or len(C) < size * size:
                return None
                
            # Tomar los primeros size * size caracteres
            P = P[:size * size].reshape(size, size)
            C = C[:size * size].reshape(size, size)
            
            # Intentar encontrar la matriz clave K donde C = KP (mod 26)
            try:
                P_matrix = Matrix(P)
                if P_matrix.det() % 26 == 0:
                    return None
                    
                P_inv = HillCipher.InvMatrixModular(P)
                K = np.matmul(C, P_inv) % 26
                
                # Verificar si la clave encontrada funciona
                test_cipher = np.matmul(K, P) % 26
                if np.array_equal(test_cipher, C):
                    return K
            except:
                pass
            
            return None
        
        # Preparar el texto
        clean_ciphertext = ''.join(c for c in ciphertext.upper() if c.isalpha())
        
        if len(clean_ciphertext) < 4:  # Necesitamos al menos una matriz 2x2
            return "El texto cifrado es demasiado corto para realizar un análisis efectivo."
            
        result = "Análisis del cifrado Hill:\n\n"
        
        # Si tenemos texto claro conocido
        if known_plaintext:
            clean_plaintext = ''.join(c for c in known_plaintext.upper() if c.isalpha())
            if len(clean_plaintext) != len(clean_ciphertext):
                return "El texto claro conocido debe tener la misma longitud que el texto cifrado."
                
            result += "Realizando ataque con texto claro conocido...\n"
            
            # Probar diferentes tamaños de matriz
            possible_sizes = find_possible_key_size(len(clean_ciphertext))
            
            for size in possible_sizes:
                key_matrix = try_known_plaintext_attack(clean_ciphertext, clean_plaintext, size)
                if key_matrix is not None:
                    result += f"\nPosible clave encontrada (matriz {size}x{size}):\n"
                    result += str(key_matrix)
                    result += "\n\nPrueba de descifrado con esta clave:\n"
                    try:
                        # Convertir la matriz a string para usar con decrypt
                        key_str = ','.join(map(str, key_matrix.flatten()))
                        decrypted = HillCipher.decrypt(clean_ciphertext, key_str)
                        result += decrypted
                    except:
                        result += "Error al intentar descifrar con la clave encontrada."
                    return result
            
            result += "\nNo se pudo encontrar una clave válida con el texto claro proporcionado."
            
        else:
            result += "Para realizar un ataque al cifrado Hill, se necesita texto claro conocido.\n"
            result += "Por favor, proporciona un fragmento de texto claro junto con su correspondiente texto cifrado."
            
        return result

# example = HillCipher.encript("ILOVEYOU", "ADBE")
# print(example)
# print(HillCipher.decript(example, "ADBE"))