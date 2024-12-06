import sys
sys.path.append('../build')
import cipher

print("\nCaesar:")
caesar = cipher.CaesarCipher()
encrypted = caesar.encrypt("Hello, World!", "3")
print(encrypted)

decrypted = caesar.decrypt(encrypted, "3")
print(decrypted)

print("Attack:")
caesar.attack(encrypted)

print("\nAffine:")
affine = cipher.AffineCipher()
encrypted = affine.encrypt("Hello, World!", "3 5")
print(encrypted)

decrypted = affine.decrypt(encrypted, "3 5")
print(decrypted)

print("Attack:")
affine.attack(encrypted)

print("\nVigenere:")
vigenere = cipher.VigenereCipher()
encrypted = vigenere.encrypt("Hello, World!", "KEY")
print(encrypted)

decrypted = vigenere.decrypt(encrypted, "KEY")
print(decrypted)

print("Attack:")
vigenere.attack(encrypted)

print("\nSubstitution:")
substitution = cipher.SubstitutionCipher()
encrypted = substitution.encrypt("Hello, World!", "qwertyuiopasdfghjklzxcvbnm")
print(encrypted)

decrypted = substitution.decrypt(encrypted, "qwertyuiopasdfghjklzxcvbnm")
print(decrypted)

print("Attack:")
substitution.attack(encrypted)