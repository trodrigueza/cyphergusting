#include "substitution_cipher.h"
#include <cctype>
#include <string>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <map>
using namespace std;

string SubstitutionCipher::encrypt(const string &plaintext, const string &key) {
  for (auto c : key) {
    if (!isalpha(c) || key.length() != 26)
      throw invalid_argument("Key should be an alphabet's permutation.");
  }
  string keyLow = "", keyUp = "";
  for (int i = 0; i < 26; i++){
    keyLow += tolower(key[i]);
    keyUp += toupper(key[i]);
  }
  map<char, char> lowMap, upMap;
  char it = 'a';
  for (char c : keyLow) {
    lowMap[it++] = c;
  }
  it = 'A';
  for (char c : keyUp) {
    upMap[it++] = c;
  }

  string ciphertext = "";
  for (char c : plaintext) {
    if (isalpha(c)) {
      ciphertext += (islower(c) ? lowMap[c] : upMap[c]);
    } else ciphertext += c;
  }
  return ciphertext;
}

string SubstitutionCipher::decrypt(const string &ciphertext, const string &key) {
  for (auto c : key) {
    if (!isalpha(c) || key.length() != 26)
      throw invalid_argument("Key should be an alphabet's permutation.");
  }
  string keyLow = "", keyUp = "";
  for (int i = 0; i < 26; i++){
    keyLow += tolower(key[i]);
    keyUp += toupper(key[i]);
  }
  map<char, char> invLow, invUp;
  for (int i = 0; i < 26; i++) {
    invLow[keyLow[i]] = 'a' + i;
    invUp[keyUp[i]] = 'A' + i;
  }

  string plaintext = "";
  for (char c : ciphertext) {
    if (isalpha(c)) {
      plaintext += (islower(c) ? invLow[c] : invUp[c]);
    } else plaintext += c;
  }
  return plaintext;
}

void SubstitutionCipher::attack(const string &ciphertext) {
  cout << "Not implemented yet.";
}
