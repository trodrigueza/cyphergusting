#include "cipher_selector.h"
#include <memory>
#include <stdexcept>
using namespace std;

unique_ptr<Cipher> CipherSelector::createCipher(const string &type) {
  if (type == "Caesar") return make_unique<CaesarCipher>();
  else throw invalid_argument("Cipher type not suported.");

}
