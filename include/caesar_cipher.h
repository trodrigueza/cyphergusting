// caesar_cipher.h
#ifndef CAESAR_CIPHER
#define CAESAR_CIPHER

#include "cipher.h"
using namespace std;

class CaesarCipher : public Cipher {
  public:
    string encrypt(const string &plaintext, const string &key) override;
    string decrypt(const string &ciphertext, const string &key) override;
};

#endif // CAESAR_CIPHER
