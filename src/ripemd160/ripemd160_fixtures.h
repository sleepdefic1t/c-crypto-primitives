/**
 * This file is part of Ark C Crypto Primitives.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#ifndef ARK_CRYPTO_C_PRIMITIVES_RIPEMD160_FIXTURES_H
#define ARK_CRYPTO_C_PRIMITIVES_RIPEMD160_FIXTURES_H

////////////////////////////////////////////////////////////////////////////////
// Sha256 Fixture Context
typedef struct ripemd160_fixture_t {
    unsigned int    size;
    char            *seed;
    char            *digest;
} Ripemd160Fixture;

////////////////////////////////////////////////////////////////////////////////
// Test Vector Constants
#define STANDARD_VECTOR_COUNT       8
#define MISMATCH_VECTOR_COUNT       5
#define RANDOM_VECTOR_COUNT         128
#define BINARY_VECTOR_COUNT         17

////////////////////////////////////////////////////////////////////////////////
// Test Vectors
static const Ripemd160Fixture standard_vectors[] = {
    #include "ripemd160_standard.fixtures"
};

static const Ripemd160Fixture mismatch_vectors[] = {
    #include "ripemd160_mismatch.fixtures"
};

static const Ripemd160Fixture random_vectors[] = {
    #include "ripemd160_random.fixtures"
};

static const Ripemd160Fixture binary_vectors[] = {
    #include "ripemd160_binary.fixtures"
};

#endif  // #define ARK_CRYPTO_C_PRIMITIVES_SHA256_FIXTURES_H
