import math
import ast

def factorizar(n):
    """
    Factoriza n mediante división de prueba.
    Retorna una tupla (p, q) si se encuentra una factorización, o None en caso contrario.
    """
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return (i, n // i)
    return None

def egcd(a, b):
    """
    Algoritmo extendido de Euclides.
    Retorna una tupla (g, x, y) tal que: a*x + b*y = g = gcd(a, b)
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    """
    Calcula el inverso modular de a módulo m.
    Si no existe, lanza una excepción.
    """
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("El inverso modular no existe")
    else:
        return x % m

def ataque_rsa(n, e, c):
    """
    Realiza el ataque RSA, permitiendo que c sea un entero o una lista/tupla de enteros.

    Parámetros:
      n: Entero, clave pública n.
      e: Entero, clave pública e.
      c: Mensaje cifrado, puede ser un entero o una lista/tupla de enteros.

    Retorna un string con el resultado del ataque.
    """
    resultado = []
    resultado.append("=== Ataque a cifrado RSA con primos pequeños ===")
    resultado.append(f"Factorizando n = {n} ...")
    factores = factorizar(n)
    if factores is None:
        resultado.append("No se pudieron encontrar factores de n.")
        return "\n".join(resultado)
    
    p, q = factores
    resultado.append("Se encontraron los factores:")
    resultado.append(f"p = {p}")
    resultado.append(f"q = {q}")
    
    # Calcular φ(n) = (p - 1) * (q - 1)
    phi = (p - 1) * (q - 1)
    
    try:
        d = modinv(e, phi)
    except Exception as ex:
        resultado.append("Error al calcular el inverso modular: " + str(ex))
        return "\n".join(resultado)
    
    resultado.append(f"Clave privada d calculada: {d}")
    
    # Verifica si c es una lista/tupla o un entero
    if isinstance(c, (list, tuple)):
        # Descifrar cada bloque individualmente
        descifrado_numeros = [pow(block, d, n) for block in c]
        resultado.append("Mensaje descifrado (números): " + str(descifrado_numeros))
        # Intentar convertir cada número a carácter (suponiendo que cada bloque representa un código ASCII)
        mensaje_texto = ""
        for num in descifrado_numeros:
            try:
                mensaje_texto += chr(num)
            except Exception:
                mensaje_texto += f"[{num}]"
        resultado.append(f"Mensaje descifrado (texto): {mensaje_texto}")
    else:
        # Si c es un entero
        m = pow(c, d, n)
        resultado.append(f"Mensaje descifrado (representación numérica): {m}")
        try:
            hex_m = hex(m)[2:]
            if len(hex_m) % 2 != 0:
                hex_m = "0" + hex_m
            mensaje = bytes.fromhex(hex_m).decode("utf-8")
            resultado.append(f"Mensaje descifrado (texto): {mensaje}")
        except Exception as ex:
            resultado.append("No se pudo convertir el mensaje a texto: " + str(ex))
    
    return "\n".join(resultado)

def parse_ciphertext(input_str):
    """
    Convierte una cadena de texto que representa un entero o una lista de enteros
    en el objeto de Python correspondiente usando ast.literal_eval.
    """
    try:
        # Esto permite convertir, por ejemplo, "12345" o "[91, 89, 114, 15]"
        return ast.literal_eval(input_str)
    except Exception as ex:
        raise ValueError("Formato de mensaje cifrado no válido: " + str(ex))
