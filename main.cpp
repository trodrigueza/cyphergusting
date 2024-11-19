#include <iostream>
#include "cipher_selector.h"
using namespace std;

int main() {
  string text, key, type;
  cin >> text >> key >> type;

  auto caesar = CipherSelector::createCipher(type);
  cout << "Ecrypted: " << caesar->encrypt(text, key) << "\n";
  cout << "Decrypted: " << caesar->decrypt(caesar->encrypt(text, key), key) << "\n";

  return 0;
}
