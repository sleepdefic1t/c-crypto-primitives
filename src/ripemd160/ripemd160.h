/**
 * This file is part of Ark C Crypto Primitives.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#ifndef ARK_CRYPTO_C_PRIMITIVES_RIPEMD160_H
#define ARK_CRYPTO_C_PRIMITIVES_RIPEMD160_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif  // #ifdef __cplusplus

////////////////////////////////////////////////////////////////////////////////
#define RIPEMD160_DIGEST_LEN 20

////////////////////////////////////////////////////////////////////////////////
void ripemd160(const uint8_t *src, size_t len, uint8_t *digest);

#ifdef __cplusplus
}
#endif  // #ifdef __cplusplus

#endif  // #define ARK_CRYPTO_C_PRIMITIVES_RIPEMD160_H
