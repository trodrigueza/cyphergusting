import random
import math

# Verifica si un número n es primo.
def is_prime(n):
  if n < 2:
    return False
  for i in range(2, int(math.sqrt(n)) + 1):
    if n % i == 0:
      return False
  return True

# Genera un número primo de 'bits' bits.
def generate_prime(bits=32):
  while True:
    p = random.getrandbits(bits)
    p |= 1  # Asegura que p sea impar.
    if is_prime(p):
      return p

# Calcula los factores primos de n y los retorna como un conjunto.
def prime_factors(n):
  factors = set()
  while n % 2 == 0:
    factors.add(2)
    n //= 2
  f = 3
  while f * f <= n:
    while n % f == 0:
      factors.add(f)
      n //= f
    f += 2
  if n > 1:
    factors.add(n)
  return factors

# Encuentra una raíz primitiva para el primo p.
def find_primitive_root(p):
  if p == 2:
    return 1
  phi = p - 1
  factors = prime_factors(phi)
  # Se busca un g tal que, para cada factor q de phi, g^(phi/q) mod p != 1.
  for g in range(2, p):
    if all(pow(g, phi // q, p) != 1 for q in factors):
      return g
  return None

# Calcula el inverso modular de a módulo m utilizando el algoritmo extendido de Euclides.
def modinv(a, m):
  def egcd(a, b):
    if a == 0:
      return b, 0, 1
    gcd, x, y = egcd(b % a, a)
    return gcd, y - (b // a) * x, x
  gcd, x, _ = egcd(a, m)
  if gcd != 1:
    return None  # No existe inverso si a y m no son coprimos.
  return x % m

# Genera la pareja de claves (pública y privada) para ElGamal.
def generate_keys(bits=32):
  p = generate_prime(bits)        # Genera un primo de 'bits' bits.
  g = find_primitive_root(p)        # Encuentra una raíz primitiva de p.
  x = random.randint(1, p - 2)        # Selecciona la clave privada aleatoriamente.
  h = pow(g, x, p)                  # Calcula h = g^x mod p.
  public_key = (p, g, h)
  private_key = x
  return public_key, private_key

# Convierte un mensaje (cadena) en bloques de enteros según un tamaño de bloque.
def message_to_blocks(message, block_size):
  m_bytes = message.encode('utf-8')  # Convierte el mensaje a bytes.
  blocks = []
  for i in range(0, len(m_bytes), block_size):
    block = m_bytes[i:i+block_size]
    # Se almacena el entero obtenido de los bytes y la longitud real del bloque.
    blocks.append((int.from_bytes(block, 'big'), len(block)))
  return blocks

# Reconstruye el mensaje original a partir de los bloques de enteros.
def blocks_to_message(blocks):
  message_bytes = bytearray()
  for m_int, length in blocks:
    b = m_int.to_bytes(length, 'big')
    message_bytes.extend(b)
  return message_bytes.decode('utf-8')

# Función de cifrado de ElGamal que opera por bloques.
def encrypt(public_key, message):
  p, g, h = public_key
  # Calcula el tamaño del bloque para que cada bloque, al convertirse en entero, sea menor que p.
  block_size = (p.bit_length() - 1) // 8
  blocks = message_to_blocks(message, block_size)
  ciphertext = []
  for m_int, length in blocks:
    y = random.randint(1, p - 2)       # Valor efímero aleatorio.
    c1 = pow(g, y, p)                 # Calcula c1 = g^y mod p.
    s = pow(h, y, p)                  # Calcula s = h^y mod p.
    c2 = (m_int * s) % p              # Calcula c2 = m * s mod p.
    ciphertext.append((c1, c2, length))
  return ciphertext

# Función de descifrado de ElGamal que opera por bloques.
def decrypt(public_key, private_key, ciphertext):
  p, _, _ = public_key
  blocks = []
  for c1, c2, length in ciphertext:
    s = pow(c1, private_key, p)        # Calcula s = c1^x mod p, donde x es la clave privada.
    s_inv = modinv(s, p)               # Calcula el inverso modular de s.
    m_int = (c2 * s_inv) % p           # Recupera el bloque original: m = c2 * s_inv mod p.
    blocks.append((m_int, length))
  return blocks_to_message(blocks)

# ejemplo
def elgamal_interface():
  print("Generando claves...")
  public_key, private_key = generate_keys(32)  # Genera claves con 32 bits.
  print("Clave pública (p, g, h):", public_key)
  print("Clave privada (x):", private_key)
  
  message = input("Ingresa el mensaje a cifrar: ")
  ciphertext = encrypt(public_key, message)
  print("Mensaje cifrado (lista de bloques):")
  print(ciphertext)
  
  decrypted_message = decrypt(public_key, private_key, ciphertext)
  print("Mensaje descifrado:")
  print(decrypted_message)

if __name__ == '__main__':
  elgamal_interface()
