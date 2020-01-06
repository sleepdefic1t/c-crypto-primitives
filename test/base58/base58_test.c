/**
 * This file is part of Ark C Crypto Primitives.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "base58/base58.h"

#include "base58/fixtures/base58_fixtures.h"

#include "test_helpers.h"

////////////////////////////////////////////////////////////////////////////////
// build and run with gcc:
// `gcc -I../../src -I../ ../../src/base58/base58.c base58_test.c -o base58_tests`
// `./base58_tests`

// build and run with gcc, with result printing:
// `gcc -I../../src -I../ ../../src/base58/base58.c base58_test.c -o base58_tests -DPRINT_RESULTS`
// `./base58_tests`

////////////////////////////////////////////////////////////////////////////////
static const char *encode_standard_success_label =
        "\nBase58 Encode Standard Tests Successful: %s"
#if defined(PRINT_RESULTS)
        "\n==================================================================="
#endif
        "\n";

int base58_encode_standard_cases() {
#if defined(PRINT_RESULTS)
    printf(
        "\n===================================================================\n"
        "\nBase58 Encode Standard Test Vectors:\n");
#endif

    int i;
    for (i = 0; i < BASE58_VECTOR_COUNT; ++i) {
        size_t resultLen =
                BASE58_ENCODED_LEN_GET(encode_decode_vectors[i].hexLen);
        char result[resultLen + 1];

        uint8_t *hexBytes = HexToBytes(encode_decode_vectors[i].hex);
        base58Encode(hexBytes,
                     encode_decode_vectors[i].hexLen,
                     result,
                     &resultLen);
        free(hexBytes);

#if defined(PRINT_RESULTS)
        PrintResult(result);
#endif

        if (strcmp(result, encode_decode_vectors[i].base58) != 0) {
            goto result;
        }
    }

    result:
    return i == BASE58_VECTOR_COUNT;
}

//////////////////////////////////////////////////////////////////////////////
static const char *decode_standard_success_label =
        "\nBase58 Decode Standard Tests Successful: %s"
#if defined(PRINT_RESULTS)
        "\n==================================================================="
#endif
        "\n";

int base58_decode_standard_cases() {
#if defined(PRINT_RESULTS)
    printf(
        "\n===================================================================\n"
        "Base58 Decode Standard Test Vectors:\n");
#endif

    int i;
    for (i = 0; i < BASE58_VECTOR_COUNT; ++i) {
        size_t resultLen =
                BASE58_DECODED_LEN_GET(encode_decode_vectors[i].base58Len);
        uint8_t result[resultLen];
        memset(result, 0, sizeof(result));

        base58Decode(encode_decode_vectors[i].base58,
                     encode_decode_vectors[i].base58Len,
                     result,
                     &resultLen);

#if defined(PRINT_RESULTS)
        PrintBytesResult(result, resultLen);
#endif

        uint8_t *hexBytes = HexToBytes(encode_decode_vectors[i].hex);
        const int matches = memcmp(result, hexBytes, resultLen) == 0;
        free(hexBytes);

        if (!matches) {
            goto result;
        }
    }

    result:
    return i == BASE58_VECTOR_COUNT;
}

////////////////////////////////////////////////////////////////////////////////
int main() {
    printf(
    "\n===================================================================\n"
    "Running Base58 Tests"
    "\n===================================================================\n");

    const int caseCount = 2;
    int result = 0;

    result += base58_encode_standard_cases();
    printf(encode_standard_success_label, result == 1 ? "true" : "false");

    result += base58_decode_standard_cases();
    printf(decode_standard_success_label, result == 2 ? "true" : "false");

    printf(
    "\n===================================================================\n"
    "%d of %d Base58 Tests Passed Successfully"
    "\n===================================================================\n\n",
    result,
    caseCount);

    return 0;
}
