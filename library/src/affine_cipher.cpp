#include "affine_cipher.h"
#include <stdexcept>
#include <iostream>
#include <numeric>
#include <map>
using namespace std;

int gcd(int a, int b) {
    a = abs(a);
    b = abs(b);
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

string AffineCipher::encrypt(const string &plaintext, const string &key) {
  int a = -1;
  int b = -1;
  string aStr = "";
  string bStr = "";
  int i = 0;
  while (key[i] != ' ' && i < key.length()) {aStr += (isdigit(key[i]) ? key[i++] : throw invalid_argument("Invalid key: `a` and `b` should be integers (Z_26), `a` should be a relative prime of 26."));}
  i++;
  while (key[i] != ' ' && i < key.length()) {bStr += (isdigit(key[i]) ? key[i++] : throw invalid_argument("Invalid key: `a` and `b` should be integers (Z_26), `a` should be a relative prime of 26."));}
  a = stoi(aStr) % 26;
  b = stoi(bStr) % 26;
  if (a == -1 || b == -1 || gcd(a, 26) != 1)
    throw invalid_argument("Invalid key: `a` and `b` should be integers (Z_26), `a` should be a relative prime of 26.");

  string ciphertext = "";
  for (char c : plaintext) {
    if (isalpha(c)) {
      ciphertext += (islower(c) ? ((c-'a') * a + b) % 26 + 'a' : ((c-'A') * a + b) % 26 + 'A');
    } else ciphertext += c;
  }
  return ciphertext;
}

string AffineCipher::decrypt(const string &ciphertext, const string &key) {
  int a = -1;
  int b = -1;
  string aStr = "";
  string bStr = "";
  int i = 0;
  while (key[i] != ' ' && i < key.length()) {aStr += (isdigit(key[i]) ? key[i++] : throw invalid_argument("Invalid key: `a` and `b` should be integers (Z_26), `a` should be a relative prime of 26."));}
  i++;
  while (key[i] != ' ' && i < key.length()) {bStr += (isdigit(key[i]) ? key[i++] : throw invalid_argument("Invalid key: `a` and `b` should be integers (Z_26), `a` should be a relative prime of 26."));}
  a = stoi(aStr) % 26;
  b = stoi(bStr) % 26;
  if (a == -1 || b == -1 || gcd(a, 26) != 1)
    throw invalid_argument("Invalid key: `a` and `b` should be integers (Z_26), `a` should be a relative prime of 26.");

  map<int, int> inv;
  inv[1] = 1; inv[3] = 9; inv[9] = 3; inv[5] = 21; inv[21] = 5; inv[7] = 15; inv[15] = 7;
  inv[11] = 19; inv[19] = 11; inv[17] = 23; inv[23] = 17; inv[25] = 25;
  string plaintext = "";
  for (char c : ciphertext) {
    if (isalpha(c)) {
      plaintext += (islower(c) ? ((((inv[a] * (c - 'a' - b))) % 26) + 26) % 26 + 'a' : ((((inv[a] * (c - 'A' - b))) % 26) + 26) % 26 + 'A');
    } else plaintext += c;
  }
  return plaintext;
}

void AffineCipher::attack(const string &text) {
  cout << "Not implemented yet.\n";
}
