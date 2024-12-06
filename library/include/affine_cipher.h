#ifndef AFFINE_CIPHER_H
#define AFFINE_CIPHER_H

#include "cipher.h"
using namespace std;

class AffineCipher : public Cipher {
  public:
    string encrypt(const string &plaintext, const string &key) override;
    string decrypt(const string &ciphertext, const string &key) override;
    void attack(const string &text) override;
};

#endif
