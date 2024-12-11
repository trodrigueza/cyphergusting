import numpy as np
from sympy import Matrix, mod_inverse

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
    detInv = mod_inverse(auxMatrix.det(), modulo)
    print(detInv)
    adjugateMatrix = auxMatrix.adjugate()
    inverseMatrix = (detInv * adjugateMatrix) % modulo
    return np.array(inverseMatrix)

matrix = CreateNSMatrixModular(10, mod)
print(matrix)
inv = CreateInvMatrixModular(matrix, mod)
print(inv)

print(np.remainder(np.matmul(matrix, inv), 26))

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