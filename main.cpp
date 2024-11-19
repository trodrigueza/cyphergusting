#include <iostream>
#include "cipher_selector.h"
using namespace std;

int main() {
  string text, key, type;
  cout << "Input the text you want to encrypt:\n";
  getline(cin, text);
  cout << "Input the key:\n";
  getline(cin, key);
  cout << "Input the cipher type:\n";
  getline(cin, type);

  auto caesar = CipherSelector::createCipher(type);
  cout << "Ecrypted: " << caesar->encrypt(text, key) << "\n";
  cout << "Decrypted: " << caesar->decrypt(caesar->encrypt(text, key), key) << "\n";

  return 0;
}
