cmake_minimum_required(VERSION 3.14)
project(CipherLibrary)

find_package(Python 3.11 COMPONENTS Interpreter Development)
find_package(pybind11 CONFIG REQUIRED)

include_directories(include)
include_directories(${Python3_INCLUDE_DIRS})

set(SRC_FILES src/caesar_cipher.cpp src/affine_cipher.cpp src/substitution_cipher.cpp src/vigenere_cipher.cpp)

Python_add_library(cipher wrapper/cipher_wrapper.cpp ${SRC_FILES})
target_link_libraries(cipher PUBLIC pybind11::headers)
set_target_properties(cipher PROPERTIES
                                INTERPROCEDURAL_OPTIMIZATION ON
                                CXX_VISIBILITY_PRESET hidden
                                VISIBILITY_INLINES_HIDDEN ON)

set_target_properties(cipher PROPERTIES
    PREFIX ""  # No "lib" prefix
    OUTPUT_NAME "cipher"  # Output name for the Python module
)
