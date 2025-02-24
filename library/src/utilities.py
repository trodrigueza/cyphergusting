import numpy as np
import math

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
def intToPermutation(index, n):
    # Permutations range between 0 and (n! - 1)
    # Step 1: Generate the permutation from the integer
    sequence = list(np.arange(n))  # Start with a list of indices
    permutation = []
    for i in range(n):
        factorial = math.factorial(n - 1 - i)  # Compute factorial
        pos = index // factorial  # Determine the position to pick based on dividing by (n-1)!
        index %= factorial  # Update the index to the remainder of said division. when equal to 0, leaves element in same place
        permutation.append(sequence.pop(pos))  # Append and remove selected element

    # Step 2: Build the permutation matrix
    matrix = np.zeros((n, n), dtype=int)
    for i, j in enumerate(permutation):
        matrix[i, j] = 1  # Place a 1 for each row-column pairing

    return matrix

# Example usage
# n = 2  # Size of the permutation matrix (4x4)
# index = 1  # Example index
# result = intToPermutation(index, n)

# print("Permutation Matrix:")
# print(result)