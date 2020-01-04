/**
 * This file is part of Ark C Crypto Primitives.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#ifndef ARK_CRYPTO_C_PRIMITIVES_BASE58_FIXTURES_H
#define ARK_CRYPTO_C_PRIMITIVES_BASE58_FIXTURES_H

#include <stddef.h>
#include <stdint.h>

////////////////////////////////////////////////////////////////////////////////
// Base58 Fixture Context
typedef struct base58_fixture_t {
    size_t          hexLen;
    const char      *hex;
    size_t          base58Len;
    const char      *base58;
} Base58Fixture;

////////////////////////////////////////////////////////////////////////////////
// Test Vector Constants
#define BASE58_VECTOR_COUNT     1000
#define BASE58_VECTOR_HEX_MAX   256

////////////////////////////////////////////////////////////////////////////////
// Test Vectors
static const Base58Fixture encode_decode_vectors[] = {
    #include "base58/fixtures/base58_encode_decode.fixtures"
};

#endif  // #define ARK_CRYPTO_C_PRIMITIVES_BASE58_FIXTURES_H