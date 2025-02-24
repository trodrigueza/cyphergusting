import random  
import math    

# Verifica si un número n es primo
def is_prime(n):
  if n < 2:
    return False 
  for i in range(2, int(math.sqrt(n)) + 1):
    if n % i == 0:
      return False  
  return True  

# Genera un candidato a número primo de una longitud dada (en bits)
def generate_prime_candidate(length):
  p = random.getrandbits(length)  # Genera un número aleatorio de "length" bits
  p |= (1 << length - 1) | 1        # Asegura que el número tenga el bit más significativo en 1 y sea impar
  return p

# Genera un número primo real, comprobando candidatos generados aleatoriamente
def generate_prime_number(length=8):
  p = generate_prime_candidate(length)  # Genera un primer candidato
  while not is_prime(p):
    p = generate_prime_candidate(length)  # Sigue generando candidatos hasta que uno sea primo
  return p

# Calcula el inverso modular de 'a' módulo 'm'
def modinv(a, m):
  # Función auxiliar que implementa el algoritmo extendido de Euclides
  def egcd(a, b):
    if a == 0:
      return b, 0, 1  # Caso base: devuelve el MCD y los coeficientes
    gcd, x1, y1 = egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y
  gcd, x, y = egcd(a, m)
  if gcd != 1:
    return None  # Si a y m no son coprimos, no existe inverso modular
  else:
    return x % m  # Retorna el inverso modular de a

# Genera un par de claves RSA (clave pública y privada)
def generate_keypair(keysize=8):
  p = generate_prime_number(keysize)
  q = generate_prime_number(keysize)  
  while q == p:
    q = generate_prime_number(keysize)  
  n = p * q                           
  phi = (p - 1) * (q - 1)             
  e = 65537                           # Valor común para el exponente público
  # Verifica que e y phi sean coprimos
  if math.gcd(e, phi) != 1:
    # Si 65537 no es adecuado, busca otro valor de e
    for i in range(3, phi, 2):
      if math.gcd(i, phi) == 1:
        e = i
        break
  d = modinv(e, phi)  # Calcula el inverso modular de e (clave privada)
  return ((e, n), (d, n))  # Retorna la clave pública y privada como tuplas

def encrypt(pk, plaintext):
  e, n = pk  
  # Cifra cada carácter convirtiéndolo a su valor ASCII y aplicando la potencia modular
  cipher = [pow(ord(char), e, n) for char in plaintext]
  return cipher

def decrypt(pk, ciphertext):
  d, n = pk  
  # Descifra cada número y lo convierte de vuelta a un carácter
  plain = [chr(pow(char, d, n)) for char in ciphertext]
  return ''.join(plain)  # Reconstruye mensaje 

# Para ejemplo 
def rsa_interface():
  choice = input("¿Deseas generar un par de claves? (S/N): ").strip().upper()
  if choice == "S":
    public, private = generate_keypair(8)  # Genera claves con 8 bits 
    print("Clave pública (e, n):", public)
    print("Clave privada (d, n):", private)
  else:
    print("Introduce la clave pública para encriptar:")
    e = int(input("Valor de e: "))
    n = int(input("Valor de n: "))
    public = (e, n)
  
  # Solicita el mensaje a cifrar
  message = input("Ingresa el mensaje a encriptar: ")
  ciphertext = encrypt(public, message)
  print("Mensaje cifrado:", ciphertext)
  
  decrypt_choice = input("¿Deseas desencriptar el mensaje? (S/N): ").strip().upper()
  if decrypt_choice == "S":
    print("Introduce la clave privada para desencriptar:")
    d = int(input("Valor de d: "))
    n = int(input("Valor de n: "))
    private = (d, n)
    decrypted_message = decrypt(private, ciphertext)
    print("Mensaje desencriptado:", decrypted_message)

def main():
  rsa_interface()  

if __name__ == '__main__':
  main()
