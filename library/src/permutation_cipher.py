import numpy as np
from math import factorial
from .utilities import toInt, toStr, intToPermutation

class PermutationCipher:

    mod = 26

    @staticmethod
    def encrypt(plainText, key):
        textSize = len(plainText)
        pairKey = key.split()

        keySize = int(pairKey[0])
        keyVal = int(pairKey[1])

        if(keySize > textSize or textSize % keySize != 0):
            raise ValueError("Key is of invalid size. Length of text must be divisible by key size.")
        
        numPermutations = factorial(keySize)

        if(keyVal > numPermutations - 1):
            raise ValueError("Key does not contain a valid permutation index. Max permutation index is " + str(numPermutations - 1))
        
        text = np.vectorize(toInt)(np.array(list(plainText.replace(" ", "").upper())))

        text = text.reshape(keySize, int(textSize / keySize))

        keyM = intToPermutation(keyVal, keySize)

        cipherText = np.matmul(keyM, text) % PermutationCipher.mod

        cipherText = np.vectorize(toStr)(cipherText.flatten())
        cipherText = ''.join(map(str, cipherText))

        return cipherText
    
    @staticmethod
    def decrypt(cipherText, key):
        textSize = len(cipherText)
        pairKey = key.split()

        keySize = int(pairKey[0])
        keyVal = int(pairKey[1])

        if(keySize > textSize or textSize % keySize != 0):
            raise ValueError("Key is of invalid size. Length of text must be divisible by key size.")
        
        numPermutations = factorial(textSize)
        if(keyVal > numPermutations - 1):
            raise ValueError("Key does not contain a valid permutation index. Max permutation index is " + str(numPermutations - 1))
        
        text = np.vectorize(toInt)(np.array(list(cipherText.replace(" ", "").upper())))

        text = text.reshape(keySize, int(textSize / keySize))

        keyM = np.transpose(intToPermutation(keyVal, keySize))

        clearText = np.matmul(keyM, text) % PermutationCipher.mod

        clearText = np.vectorize(toStr)(clearText.flatten())
        clearText = ''.join(map(str, clearText))

        return clearText

# example = PermutationCipher.encript("ILOVEYOUABCD", "6 8")
# print(example)
# print(PermutationCipher.decript(example, "6 8"))

