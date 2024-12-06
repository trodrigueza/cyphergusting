#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "cipher.h"
#include "caesar_cipher.h"
#include "affine_cipher.h"
#include "substitution_cipher.h"
#include "vigenere_cipher.h"

namespace py = pybind11;

PYBIND11_MODULE(cipher, m) {
    py::class_<Cipher>(m, "Cipher");

    py::class_<CaesarCipher, Cipher>(m, "CaesarCipher")
        .def(py::init<>())
        .def("encrypt", &CaesarCipher::encrypt)
        .def("decrypt", &CaesarCipher::decrypt)
        .def("attack", &CaesarCipher::attack);
    
    py::class_<AffineCipher, Cipher>(m, "AffineCipher")
        .def(py::init<>())
        .def("encrypt", &AffineCipher::encrypt)
        .def("decrypt", &AffineCipher::decrypt)
        .def("attack", &AffineCipher::attack);

    py::class_<SubstitutionCipher, Cipher>(m, "SubstitutionCipher")
        .def(py::init<>())
        .def("encrypt", &SubstitutionCipher::encrypt)
        .def("decrypt", &SubstitutionCipher::decrypt)
        .def("attack", &SubstitutionCipher::attack);

    py::class_<VigenereCipher, Cipher>(m, "VigenereCipher")
        .def(py::init<>())
        .def("encrypt", &VigenereCipher::encrypt)
        .def("decrypt", &VigenereCipher::decrypt)
        .def("attack", &VigenereCipher::attack);
}

/*
clang++ -shared -std=c++17 -undefined dynamic_lookup \
    $(python3.11-config --includes) \
    $(python3.11-config --ldflags) \
    -fPIC \
    cipher_wrapper.cpp -o cipher$(python3.11-config --extension-suffix) -fPIC `python3.11 -m pybind11 --includes` -I include src/*.cpp
*/