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
    def attack(plainText, cipherText):
        #wip
        return 0

# example = HillCipher.encript("ILOVEYOU", "ADBE")
# print(example)
# print(HillCipher.decript(example, "ADBE"))