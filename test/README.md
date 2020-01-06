
# ARK C Crypto Primitives Tests

GCC build and run commands from the `./test/` dir.

## Base58

### Base58: Compile and Run Tests with GCC

1) `gcc -I../src -I../test ../src/base58/base58.c base58/base58_test.c -o base58_tests`
2) `./base58_tests`

Optionally print Base58 Encoding/Decoding results to the console:

1) `gcc -I../src -I../test ../src/base58/base58.c base58/base58_test.c -o base58_tests -DPRINT_RESULTS`
2) `./base58_tests`

### Base58Check: Compile and Run Tests with GCC

1) `gcc -I../src -I../test ../src/base58/base58_check.c ../src/base58/base58.c ../src/sha256/sha256.c base58/base58_check_test.c -o base58_check_tests`
2) `./base58_check_tests`

Optionally print Base58 Encoding/Decoding results to the console:

1) `gcc -I../src -I../test ../src/base58/base58_check.c ../src/base58/base58.c ../src/sha256/sha256.c base58/base58_check_test.c -o base58_check_tests -DPRINT_RESULTS`
2) `./base58_check_tests`

## Ripemd160

### Ripemd160: Compile and Run Tests with GCC

1) `gcc -I../src -I../test ../src/ripemd160/ripemd160.c ripemd160/ripemd160_test.c -o ripemd160_tests`
2) `./ripemd160_tests`

Optionally print Ripemd160 results to the console:

1) `gcc -I../src -I../test ../src/ripemd160/ripemd160.c ripemd160/ripemd160_test.c -o ripemd160_tests -DPRINT_RESULTS`
2) `./ripemd160_tests`

## Sha256

### Sha256: Compile and Run Tests with GCC

1) `gcc -I../src -I../test ../src/sha256/sha256.c sha256/sha256_test.c -o sha256_tests`
2) `./sha256_tests`

Optionally print Sha256 results to the console:

1) `gcc -I../src -I../test ../src/sha256/sha256.c sha256/sha256_test.c -o sha256_tests -DPRINT_RESULTS`
2) `./sha256_tests`
