#include "cipher_selector.h"
#include <memory>
#include <stdexcept>
using namespace std;

unique_ptr<Cipher> CipherSelector::createCipher(const string &type) {
  if (type == "1") return make_unique<CaesarCipher>();
  else if (type == "2") return make_unique<SubstitutionCipher>();
  else if (type == "3") return make_unique<AffineCipher>();
  else if (type == "4") return make_unique<VigenereCipher>();
  else throw invalid_argument("Choose one of the valid options.");

}
