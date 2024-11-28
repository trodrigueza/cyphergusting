#include "vigenere_cipher.h"
#include <cctype>
#include <stdexcept>
#include <iostream>

string VigenereCipher::encrypt(const string &plaintext, const string &key) {
  int m = key.length();
  int n = plaintext.length();
  for (auto c : key) {
    if (!isalpha(c))
      throw std::invalid_argument("Key should consist of alphabetic characters.");
  }
  if (n < m)
    throw std::invalid_argument("Plaintext should not be shorter than key.");

  string lowKey = "";
  string upKey = "";
  for (char c : key) {
    lowKey += tolower(c);
    upKey += toupper(c);
  }

  string ciphertext;
  ciphertext.reserve(n);
  for (int i = 0; i < n; i++) {
    if (isalpha(plaintext[i])) {
      ciphertext += islower(plaintext[i]) ? (plaintext[i] - 'a' + lowKey[i % m] - 'a') % 26 + 'a' : (plaintext[i] - 'A' + upKey[i % m] - 'A') % 26 + 'A';
    } else ciphertext += plaintext[i];
  }
  return ciphertext;
}

string VigenereCipher::decrypt(const string &ciphertext, const string &key) {
  int m = key.length();
  int n = ciphertext.length();
  for (auto c : key) {
    if (!isalpha(c))
      throw std::invalid_argument("Key should consist of alphabetic characters.");
  }
  if (n < m)
    throw std::invalid_argument("Plaintext should not be shorter than key.");

  string lowKey = "";
  string upKey = "";
  for (char c : key) {
    lowKey += tolower(c);
    upKey += toupper(c);
  }

  string plaintext;
  plaintext.reserve(n);
  for (int i = 0; i < n; i++) {
    if (isalpha(ciphertext[i])) {
      plaintext += islower(ciphertext[i]) ? (((ciphertext[i] - lowKey[i % m]) % 26) + 26) % 26 + 'a' : (((ciphertext[i] - upKey[i % m]) % 26) + 26) % 26 + 'A';
    } else plaintext += ciphertext[i];
  }
  return plaintext;
}

void VigenereCipher::attack(const string &text) {
  cout << "Not implemented yet.\n";
}
