/**
 * This file is part of Ark C Crypto Primitives.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#ifndef ARK_CRYPTO_C_PRIMITIVES_BASE58_CHECK_FIXTURES_H
#define ARK_CRYPTO_C_PRIMITIVES_BASE58_CHECK_FIXTURES_H

#include <stddef.h>
#include <stdint.h>

////////////////////////////////////////////////////////////////////////////////
// Base58Check Fixtures
typedef struct base58_check_fixture_t {
    size_t          hexLen;
    const char      *hex;
    size_t          base58CheckLen;
    const char      *base58Check;
} Base58CheckFixture;

// Base58Check Invalid Decoding
typedef struct base58_check_invalid_fixture_t {
    size_t          base58CheckLen;
    const char      *base58Check;
} Base58CheckInvalidFixture;

////////////////////////////////////////////////////////////////////////////////
// Test Vector Constants
#define BASE58_CHECK_VECTOR_COUNT       50
#define BASE58_CHECK_INVALID_COUNT      4

////////////////////////////////////////////////////////////////////////////////
// Test Vectors
static const Base58CheckFixture check_valid_vectors[] = {
    #include "base58/fixtures/base58_check_valid.fixtures"
};

static const Base58CheckInvalidFixture check_invalid_vectors[] = {
    #include "base58/fixtures/base58_check_invalid.fixtures"
};

#endif  // #define ARK_CRYPTO_C_PRIMITIVES_BASE58_CHECK_FIXTURES_H
