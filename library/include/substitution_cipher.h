#ifndef SUBSTITUTION_H
#define SUBSTITUTION_H

#include "cipher.h"
using namespace std;

class SubstitutionCipher : public Cipher {
  public:
    string encrypt(const string &plaintext, const string &key) override;
    string decrypt(const string &ciphertext, const string &key) override;
    void attack(const string &text) override;
};

#endif
