
# Ripemd160

## Features

- Adapted from [OpenSSL](https://github.com/openssl/openssl) and [Nayuki's Bitcoin cryptography library](https://github.com/nayuki/Bitcoin-Cryptography-Library).
- Little-Endian Implementation.
- Statically Allocated.
- IoT friendly.

This implementation is currently:

- **NOT** benchmarked.
- **NOT** tested against side-channel attacks.

## Compile and Run Tests with GCC

1) `gcc ripemd160.c ripemd160_test.c -o ripemd160`
2) `./ripemd160`

## More Information

- [ESAT RIPEMD-160](https://homes.esat.kuleuven.be/~bosselae/ripemd160.html)
- [openSSL Ripemd160](https://www.openssl.org/docs/man1.0.2/man3/ripemd.html) | [github](https://github.com/openssl/openssl)
- [Nayuki's Bitcoin Cryptography Library](https://www.nayuki.io/page/bitcoin-cryptography-library) | [github](https://github.com/nayuki/Bitcoin-Cryptography-Library)
