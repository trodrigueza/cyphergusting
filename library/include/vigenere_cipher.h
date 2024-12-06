// vigenere_cipher.h
#ifndef VIGENERE_CIPHER_H
#define VIGENERE_CIPHER_H

#include "cipher.h"

class VigenereCipher : public Cipher {
  public:
    string encrypt(const string &plaintext, const string &key) override;
    string decrypt(const string &ciphertext, const string &key) override;
    void attack(const string &text) override;
};

#endif
