
# Base58

## Base58 Encoding/Decoding

### Base58: Features

- Adapted from [BCrypto](https://github.com/bcoin-org/bcrypto/).
- Statically Allocated.
- IoT friendly.

### Base58: Compile and Run Tests with GCC

1) `gcc base58.c base58_test.c -o base58`
2) `./base58`

Optionally print Base58 Encoding/Decoding results to the console:

1) `gcc base58.c base58_test.c -o base58 -DPRINT_RESULTS`
2) `./base58`

## Base58Check Encoding/Decoding

### Base58Check: Features

- Original implementation.
- Fixtures adapted from  from [bs58check](https://github.com/bitcoinjs/bs58check).
- Statically Allocated.
- IoT friendly.

### Base58Check: Compile and Run Tests with GCC

1) `gcc -I../ base58_check_test.c base58_check.c base58.c ../sha256/sha256.c -o base58_check`
2) `./base58_check`

Optionally print Base58 Encoding/Decoding results to the console:

1) `gcc -I../ base58_check_test.c base58_check.c base58.c ../sha256/sha256.c -o base58_check -DPRINT_RESULTS`
2) `./base58_check`

## More Information

- [IETF: The Base58 Encoding Scheme](https://tools.ietf.org/html/draft-msporny-base58-01)
- [Bitcoin WIKI: Base58 Check Encoding](https://en.bitcoin.it/wiki/Base58Check_encoding)
