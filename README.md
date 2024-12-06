Implementing some classic Cryptosistems.

Run `library/examples/cipher_eg` for example.

Considerations:
- Python module: `library/build/cipher.so`. In `library/examples/main.py` it is imported from `../build`.
- `library/CMakeLists.txt` is for building `library/build/cipher.so`.

Types supported:
- Caesar.
- Substitution.
- Affine.
- Vigenere.
