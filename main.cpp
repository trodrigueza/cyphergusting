#include <iostream>
#include "cipher_selector.h"
using namespace std;

int main() {
  string obj;
  string text, key, type;

  cout << "Encrypt (y/n): ";
  getline(cin, obj);

  if (obj == "y") {
    cout << "Input the text you want to encrypt:\n";
    getline(cin, text);
    cout << "Input the key: ";
    getline(cin, key);
    cout << "Input the cipher type: ";
    getline(cin, type);

    auto cipher = CipherSelector::createCipher(type);
    cout << "Ecrypted: " << cipher->encrypt(text, key) << "\n";
    // cout << "Decrypted: " << cypher->decrypt(cypher->encrypt(text, key), key) << "\n";
  } else {
    cout << "Input the text you want to decrypt:\n";
    getline(cin, text);
    cout << "Input the cipher type: ";
    getline(cin, type);

    auto decipher = CipherSelector::createCipher(type);
    cout << "Decrypted:" << "\n";
    decipher->attack(text);
  }
  return 0;
}

// g++ -std=c++17 -I include src/*.cpp main.cpp -o cipher_eg
