#include <iostream>
#include "cipher_selector.h"
using namespace std;

void printMenu() {
  cout << "   1 --> Encrypt.\n";
  cout << "   2 --> Decrypt. \n";
  cout << "   3 --> Attack.\n\n> ";
}

void printType() {
  cout << "\nInput the cipher type:\n\n";
  cout << "   1 --> Caesar.\n\n";
  cout << "   2 --> Substitution.\n\n";
  cout << "   3 --> Affine.\n\n> ";
}

int main() {
  string obj;
  string text, key, type;
  cout << "\n----------------------------------------------------\n";
  cout << "Hi! Choose one of the options:\n\n";
  printMenu();
  getline(cin, obj);

  if (obj == "1") {
    cout << "\nInput the text you want to encrypt:\n\n> ";
    getline(cin, text);

    cout << "\nInput the key:\n\n> ";
    getline(cin, key);

    printType();
    getline(cin, type);

    auto cipher = CipherSelector::createCipher(type);
    cout << "\nEncrypted text:\n\n> " << cipher->encrypt(text, key) << "\n";

  } else if (obj == "2") {
    cout << "\nInput the text you want to decrypt:\n\n> ";
    getline(cin, text);

    cout << "\nInput the key:\n\n> ";
    getline(cin, key);

    printType();
    getline(cin, type);

    auto decipher = CipherSelector::createCipher(type);
    cout << "\nDecrypted text:\n\n> " << decipher->decrypt(text, key) << "\n";

  } else {
    cout << "\nInput the text you want to decrypt:\n\n> ";
    getline(cin, text);

    printType();
    getline(cin, type);

    auto decipher = CipherSelector::createCipher(type);
    cout << "\nDecrypted text:\n\n> " << "\n";
    decipher->attack(text);

  }
  cout << "\n----------------------------------------------------\n";
  return 0;
}

// g++ -std=c++17 -I include src/*.cpp main.cpp -o cipher_eg
