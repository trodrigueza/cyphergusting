def frequency_analysis(text):
    """Cuenta la frecuencia de cada letra (solo alfabético, ignorando espacios y signos)"""
    # Convertimos a mayúsculas para homogeneizar y filtramos solo letras
    text = ''.join(filter(str.isalpha, text.upper()))
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    return freq

def index_of_coincidence(text):
    """
    Calcula el Índice de Coincidencia (IC) de un texto.
    IC = [Σ (f_i*(f_i-1))] / [N*(N-1)]
    donde f_i es la frecuencia de la letra i y N es la longitud del texto.
    """
    # Convertimos a mayúsculas y extraemos solo letras
    text = ''.join(filter(str.isalpha, text.upper()))
    N = len(text)
    if N <= 1:
        return 0
    freq = frequency_analysis(text)
    numerator = sum(f * (f - 1) for f in freq.values())
    denominator = N * (N - 1)
    return numerator / denominator

# Ejemplo de uso:
if __name__ == '__main__':
    sample_text = "GTEHTNZ"  # criptograma obtenido de un cifrado (por ejemplo, Vigenère)
    freq = frequency_analysis(sample_text)
    ic = index_of_coincidence(sample_text)
    print("Frecuencias:", freq)
    print("Índice de Coincidencia:", ic)
