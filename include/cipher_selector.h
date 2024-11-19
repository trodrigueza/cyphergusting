#ifndef CIPHER_SELECTOR_H
#define CIPHER_SELECTOR_H

#include "cipher.h"
#include "caesar_cipher.h"
#include <memory>
#include <string>
using namespace std;

class CipherSelector {
  public:
    static unique_ptr<Cipher> createCipher(const string &type);
};

#endif // CIPHER_SELECTOR_H
