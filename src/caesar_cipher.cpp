#include "caesar_cipher.h"
#include <cctype>

string CaesarCipher::encrypt(const string &plaintext, const string &key) {
  const int shift = stoi(key);
  string ciphertext = "";
  for (char c : plaintext) {
    if (isalpha(c)) {
      char guide = islower(c) ? 'a' : 'A';
      ciphertext += ((c - guide + shift) % 26) + guide;
    } else ciphertext += c; // ' '
  }
  return ciphertext;
}

string CaesarCipher::decrypt(const string &ciphertext, const string &key) {
  const int shift = stoi(key);
  string plaintext = "";
  for (char c : ciphertext) {
    if (isalpha(c)) {
      char guide = islower(c) ? 'a' : 'A';
      plaintext += ((c - guide - shift + 26) % 26) + guide;
    } else plaintext += c; // ' '
  }
  return plaintext;
}
