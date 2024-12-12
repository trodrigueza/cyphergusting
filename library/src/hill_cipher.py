import numpy as np
from sympy import Matrix, mod_inverse
from math import sqrt

mod = 26

@staticmethod
def toInt(a:str):
    if a.isalpha():
        return ord(a) - ord("A")
    else:
        raise ValueError("Not alphabetic")

@staticmethod    
def toStr(a:int):
    return chr(a + ord("A"))

@staticmethod
def CheckValidKey(plaintext, key:str, modulo):
    dim = sqrt(len(key))
    if(dim.is_integer() and dim <= len(plaintext) and len(plaintext) % dim == 0):
        matrix = np.array(list(key))
        matrix = matrix.reshape(int(dim), int(dim))
        matrix = np.vectorize(toInt)(matrix)
        auxMatrix = Matrix(matrix)
        det = auxMatrix.det()
        if(np.gcd(det, 26) == 1):
            return matrix
        else:
            raise ValueError("Key is not modularly invertible")
    else:
        raise ValueError("Key is not a valid square matrix")

#Key Inverse Generation
@staticmethod
def InvMatrixModular(matrix, modulo):
    auxMatrix = Matrix(matrix)
    detInv = mod_inverse(auxMatrix.det(), modulo)
    adjugateMatrix = auxMatrix.adjugate()
    inverseMatrix = (detInv * adjugateMatrix) % modulo
    return np.array(inverseMatrix)

# matrix = CreateNSMatrixModular(10, mod)
# print(matrix)
# inv = CreateInvMatrixModular(matrix, mod)
# print(inv)

# print(np.remainder(np.matmul(matrix, inv), 26))

class HillCipher:
    @staticmethod
    def encript(plainText, key, modulo):
        text = np.vectorize(toInt)(np.array(list(plainText.replace(" ", "").upper())))
        keyM = CheckValidKey(plainText, key, modulo)

        sizeText = len(text)
        sizeBlock = len(keyM)

        text = text.reshape(sizeBlock, int(sizeText / sizeBlock))

        cipherText = np.matmul(keyM, text) % 26

        cipherText = np.vectorize(toStr)(cipherText.flatten())
        cipherText = ''.join(map(str, cipherText))

        return cipherText
    
    @staticmethod
    def decript(cipherText, key, modulo):
        text = np.vectorize(toInt)(np.array(list(cipherText.replace(" ", "").upper())))
        keyM = CheckValidKey(cipherText, key, modulo)

        sizeText = len(text)
        sizeBlock = len(keyM)

        text = text.reshape(sizeBlock, int(sizeText / sizeBlock))

        invKey = InvMatrixModular(keyM, modulo)

        plainText = np.matmul(invKey, text) % 26

        plainText = np.vectorize(toStr)(plainText.flatten())
        plainText = ''.join(map(str, plainText))

        return plainText
    
    @staticmethod
    def attack(plainText, cipherText):
        #wip
        return 0

print(HillCipher.encript("ILOVEYOU", "ADBE", mod))
print(HillCipher.decript("MUQIYDSX", "ADBE", mod))