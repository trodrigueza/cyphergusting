import random
import math

# Parámetros de la curva: y^2 = x^3 + a*x + b (mod p)
p = 97       # Campo primo
a = 2
b = 3

# Punto base (generador) de la curva (se asume que es un punto válido)
G = (3, 6)

# Función para calcular el inverso modular de x módulo p
def inv_mod(x, p):
  return pow(x, -1, p)

# Suma de dos puntos en la curva elíptica
def point_add(P, Q):
  # Si uno de los puntos es el punto en el infinito (None), devuelve el otro
  if P is None:
    return Q
  if Q is None:
    return P

  (x1, y1) = P
  (x2, y2) = Q

  # Si los puntos son opuestos, la suma es el punto en el infinito
  if x1 == x2 and (y1 + y2) % p == 0:
    return None

  # Si P y Q son distintos
  if P != Q:
    s = ((y2 - y1) * inv_mod(x2 - x1, p)) % p
  else:
    # Duplicación de punto
    s = ((3 * x1 * x1 + a) * inv_mod(2 * y1, p)) % p

  x3 = (s * s - x1 - x2) % p
  y3 = (s * (x1 - x3) - y1) % p
  return (x3, y3)

# Multiplicación escalar: calcula k * P usando algoritmo de doble y suma
def scalar_mult(k, P):
  result = None  # Representa el punto en el infinito
  addend = P

  while k:
    if k & 1:
      result = point_add(result, addend)
    addend = point_add(addend, addend)
    k //= 2
  return result

# Comprueba si un punto P = (x, y) está en la curva
def is_on_curve(P):
  if P is None:
    return True
  x, y = P
  return (y * y - (x * x * x + a * x + b)) % p == 0

# Genera la pareja de claves para ECC
def generate_keys():
  # Clave privada d (elegida aleatoriamente)
  d = random.randint(1, p - 1)
  # Clave pública Q = d * G
  Q = scalar_mult(d, G)
  return d, Q

# Negación de un punto: -P = (x, -y mod p)
def point_neg(P):
  if P is None:
    return None
  x, y = P
  return (x, (-y) % p)

# Cifrado EC-ElGamal:
# Dado el punto mensaje M y la clave pública Q,
# se elige un k aleatorio y se calcula:
#   C1 = k * G
#   C2 = M + k * Q
def ecc_encrypt(Q, M):
  k = random.randint(1, p - 1)
  C1 = scalar_mult(k, G)
  kQ = scalar_mult(k, Q)
  C2 = point_add(M, kQ)
  return (C1, C2)

# Descifrado:
# Con la clave privada d y el cifrado (C1, C2), se recupera M:
#   M = C2 - d * C1
def ecc_decrypt(d, ciphertext):
  C1, C2 = ciphertext
  dC1 = scalar_mult(d, C1)
  M = point_add(C2, point_neg(dC1))
  return M

# Interfaz de usuario para la demostración
def ecc_interface():
  print("Parámetros de la curva:")
  print(" p =", p, ", a =", a, ", b =", b)
  print("Punto base G =", G)
  
  # Genera claves
  d, Q = generate_keys()
  print("Clave privada d =", d)
  print("Clave pública Q =", Q)
  
  print("Ingrese el mensaje a cifrar representado como un punto en la curva.")
  x = int(input("Coordenada x: "))
  y = int(input("Coordenada y: "))
  M = (x, y)
  if not is_on_curve(M):
    print("El punto ingresado no está en la curva. Saliendo.")
    return
  
  ciphertext = ecc_encrypt(Q, M)
  print("Mensaje cifrado:")
  print(" C1 =", ciphertext[0])
  print(" C2 =", ciphertext[1])
  
  decrypted = ecc_decrypt(d, ciphertext)
  print("Mensaje descifrado:")
  print(decrypted)

if __name__ == '__main__':
  ecc_interface()
