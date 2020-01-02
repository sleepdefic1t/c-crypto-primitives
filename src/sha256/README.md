
# Sha256

## Features

- Adapted from [OpenSSL](https://github.com/openssl/openssl).
- [CAVP](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program) Compliant.
- Uses [NIST Test Vectors](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Secure-Hashing).
- Big-Endian Implementation.
- Statically Allocated.
- IoT friendly.

This implementation is currently:

- **NOT** benchmarked.
- **NOT** tested against side-channel attacks.
- **NOT** tested using Monte Carlo vectors.
- **NOT** [CAVP](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program) Validated.

## Compile and Run Tests with GCC

1) `gcc sha256.c sha256_test.c -o sha256`
2) `./sha256`

## More Information

- [NIST Secure Hash Standard](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- [NIST Sha256 Cryptographic Standards and Guidelines [PDF]](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf)
- [NIST Sha Test Data [PDF]](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf)
- [SHA Test Vectors for Hashing Byte-Oriented Messages [ZIP]](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip)
