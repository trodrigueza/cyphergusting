import numpy as np
from sympy import Matrix

mod = 26

def CreateNSMatrixModular(n:int, modulo):
    while(True):
        matrix = np.random.random_integers(1, modulo, (n, n))
        auxMatrix = Matrix(matrix)
        det = auxMatrix.det() % modulo
        if(np.gcd(det, 26) == 1):
            print(det)
            return matrix

def CreateInvMatrixModular(matrix, modulo):
    auxMatrix = Matrix(matrix)
    invMatrix = auxMatrix.inv_mod(modulo)
    return np.array(invMatrix)

matrix = CreateNSMatrixModular(5, mod)
inv = CreateInvMatrixModular(matrix, mod)

print(matrix)
print(inv)

class HillCipher:
    def encript(plainText, key):
        #wip
        return 0
    
    def decript(cipherText, key):
        #wip
        return 0
    
    def attack(plainText, cipherText):
        #wip
        return 0