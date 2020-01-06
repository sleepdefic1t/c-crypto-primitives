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
#include <stdlib.h>
#include <stdio.h>

#include "ripemd160/ripemd160.h"

#include "ripemd160/fixtures/ripemd160_fixtures.h"

#include "test_helpers.h"

////////////////////////////////////////////////////////////////////////////////
// build and run with gcc:
// `gcc -I../../src -I../ ../../src/ripemd160/ripemd160.c ripemd160_test.c -o ripemd160_tests`
// `./ripemd160_tests`

// build and run with gcc, with result printing:
// `gcc -I../../src -I../ ../../src/ripemd160/ripemd160.c ripemd160_test.c -o ripemd160_tests -DPRINT_RESULTS`
// `./ripemd160_tests`

////////////////////////////////////////////////////////////////////////////////
static const char *standard_success_label =
        "\nRipemd160 Standard Tests Successful: %s"
#if defined(PRINT_RESULTS)
        "\n================================================"
#endif
        "\n";

int ripemd160_standard_cases() {
#if defined(PRINT_RESULTS)
    printf("\n================================================\n"
           "\nRipemd160 Standard Test Vectors:\n");
#endif

    int i;
    for (i = 0; i < STANDARD_VECTOR_COUNT; ++i) {
        uint8_t result[RIPEMD160_DIGEST_LEN] = { 0 };

        uint8_t *asciiBytes = AsciiToBytes(standard_vectors[i].seed);
        ripemd160(asciiBytes, standard_vectors[i].size, result);
        free(asciiBytes);

#if defined(PRINT_RESULTS)
        PrintBytesResult(result, RIPEMD160_DIGEST_LEN);
#endif

        uint8_t *hexBytes = HexToBytes(standard_vectors[i].digest);
        const int matches = memcmp(result, hexBytes, RIPEMD160_DIGEST_LEN) == 0;
        free(hexBytes);

        if (!matches) {
            goto result;
        }
    }

    result:
    return i == STANDARD_VECTOR_COUNT;
}

////////////////////////////////////////////////////////////////////////////////
static const char *mismatch_success_label =
        "\nRipemd160 Mismatch Tests Successful: %s"
#if defined(PRINT_RESULTS)
        "\n================================================"
#endif
        "\n";

int ripemd160_mismatch_cases() {
#if defined(PRINT_RESULTS)
    printf("\n================================================\n"
           "\nRipemd160 Mismatch Test Vectors:\n");
#endif

    int i;
    for (i = 0; i < MISMATCH_VECTOR_COUNT; ++i) {
        uint8_t result[RIPEMD160_DIGEST_LEN] = { 0 };

        uint8_t *asciiBytes = AsciiToBytes(mismatch_vectors[i].seed);
        ripemd160(asciiBytes, mismatch_vectors[i].size, result);
        free(asciiBytes);

#if defined(PRINT_RESULTS)
        PrintBytesResult(result, RIPEMD160_DIGEST_LEN);
#endif

        uint8_t *hexBytes = HexToBytes(mismatch_vectors[i].digest);
        const int matches = memcmp(result, hexBytes, RIPEMD160_DIGEST_LEN) == 0;
        free(hexBytes);

        // Mismatch cases should not match
        if (matches) {
            goto result;
        }
    }

    result:
    return i == MISMATCH_VECTOR_COUNT;
}

////////////////////////////////////////////////////////////////////////////////
static const char *random_success_label =
        "\nRipemd160 Random Tests Successful: %s"
#if defined(PRINT_RESULTS)
        "\n================================================"
#endif
        "\n";

int ripemd160_random_cases() {
#if defined(PRINT_RESULTS)
    printf("\n================================================\n"
           "\nRipemd160 Random Test Vectors:\n");
#endif

    int i;
    for (i = 0; i < RANDOM_VECTOR_COUNT; ++i) {
        uint8_t result[RIPEMD160_DIGEST_LEN] = { 0 };

        uint8_t *asciiBytes = AsciiToBytes(random_vectors[i].seed);
        ripemd160(asciiBytes, random_vectors[i].size, result);
        free(asciiBytes);

#if defined(PRINT_RESULTS)
        PrintBytesResult(result, RIPEMD160_DIGEST_LEN);
#endif

        uint8_t *hexBytes = HexToBytes(random_vectors[i].digest);
        const int matches = memcmp(result, hexBytes, RIPEMD160_DIGEST_LEN) == 0;
        free(hexBytes);

        if (!matches) {
            goto result;
        }
    }

    result:
    return i == RANDOM_VECTOR_COUNT;
}

////////////////////////////////////////////////////////////////////////////////
static const char *binary_success_label =
        "\nRipemd160 Binary Tests Successful: %s"
#if defined(PRINT_RESULTS)
        "\n================================================"
#endif
        "\n";

int ripemd160_binary_cases() {
#if defined(PRINT_RESULTS)
    printf("\n================================================\n"
           "\nRipemd160 Binary Test Vectors:\n");
#endif

    int i;
    for (i = 0; i < BINARY_VECTOR_COUNT; ++i) {
        uint8_t result[RIPEMD160_DIGEST_LEN] = { 0 };

        uint8_t *hexBytes = HexToBytes(binary_vectors[i].seed);
        ripemd160(hexBytes, binary_vectors[i].size, result);
        free(hexBytes);

#if defined(PRINT_RESULTS)
        PrintBytesResult(result, RIPEMD160_DIGEST_LEN);
#endif

        uint8_t *msgBytes = HexToBytes(binary_vectors[i].digest);
        const int matches = memcmp(result, msgBytes, RIPEMD160_DIGEST_LEN) == 0;
        free(msgBytes);

        if (!matches) {
            goto result;
        }
    }

    result:
    return i == BINARY_VECTOR_COUNT;
}

////////////////////////////////////////////////////////////////////////////////
int main() {
    printf("\n================================================\n"
           "Running Ripemd160 Tests"
           "\n================================================\n");

    const int caseCount = 4;
    int result = 0;;

    result += ripemd160_standard_cases();
    printf(standard_success_label, result == 1 ? "true" : "false");

    result += ripemd160_mismatch_cases();
    printf(mismatch_success_label, result == 2 ? "true" : "false");

    result += ripemd160_random_cases();
    printf(random_success_label, result == 3 ? "true" : "false");

    result += ripemd160_binary_cases();
    printf(binary_success_label, result == 4 ? "true" : "false");

    printf("\n================================================\n"
           "%d of %d Ripemd160 Tests Passed Successfully"
           "\n================================================\n\n",
           result,
           caseCount);

    return 0;
}
