/**
 * This file is part of Ark C Crypto Primitives.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#ifndef ARK_CRYPTO_C_PRIMITIVES_BASE58_CHECK_H
#define ARK_CRYPTO_C_PRIMITIVES_BASE58_CHECK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif  // #ifdef __cplusplus

////////////////////////////////////////////////////////////////////////////////
// Base58-encoded output is ~138% of the size of the source.
#ifndef BASE58_ENCODED_LEN_GET
#define BASE58_ENCODED_LEN_GET(x) ((x) * 138 / 100 + 1)
#endif  // #ifndef BASE58_ENCODED_LEN_GET

// Base58-decoded output is ~73% of the size of the source.
#ifndef BASE58_DECODED_LEN_GET
#define BASE58_DECODED_LEN_GET(x) ((x) * 733 / 1000 + 1)
#endif  // #ifndef BASE58_DECODED_LEN_GET

////////////////////////////////////////////////////////////////////////////////
int base58CheckEncode(const uint8_t *data,
                      size_t dataLen,
                      char *str,
                      size_t *strLen);

int base58CheckDecode(const char *str,
                      size_t strLen,
                      uint8_t *data,
                      size_t *dataLen);

#ifdef __cplusplus
}
#endif  // #ifdef __cplusplus

#endif  // #define ARK_CRYPTO_C_PRIMITIVES_BASE58_CHECK_H
