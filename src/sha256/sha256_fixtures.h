/**
 * This file is part of Ark C Crypto Primitives.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#ifndef ARK_CRYPTO_C_PRIMITIVES_SHA256_FIXTURES_H
#define ARK_CRYPTO_C_PRIMITIVES_SHA256_FIXTURES_H

////////////////////////////////////////////////////////////////////////////////
// Sha256 Fixture Context
typedef struct sha256_fixture_t {
    unsigned int    width;
    char            *seed;
    char            *digest;
} Sha256Fixture;

////////////////////////////////////////////////////////////////////////////////
// Test Vector Constants
#define SHORT_MESSAGE_COUNT     65
#define LONG_MESSAGE_COUNT      64

////////////////////////////////////////////////////////////////////////////////
// Test Vectors
static const Sha256Fixture short_message[] = {
    #include "sha256_short.fixtures"
};

static const Sha256Fixture long_message[] = {
    #include "sha256_long.fixtures"
};

#endif  // #define ARK_CRYPTO_C_PRIMITIVES_SHA256_FIXTURES_H
