/**
 * This file is part of Ark C Crypto Primitives.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "sha256/sha256.h"

#include "sha256/fixtures/sha256_fixtures.h"

#include "test_helpers.h"

////////////////////////////////////////////////////////////////////////////////
// build and run with gcc:
// `gcc -I../../src -I../ ../../src/sha256/sha256.c sha256_test.c -o sha256_tests`
// `./sha256_tests`

// build and run with gcc, with result printing:
// `gcc -I../../src -I../ ../../src/sha256/sha256.c sha256_test.c -o sha256_tests -DPRINT_RESULTS`
// `./sha256_tests`

////////////////////////////////////////////////////////////////////////////////
static const char *example_success_label =
    "\nSha256 Basic Example Successful: %s"
#if defined(PRINT_RESULTS)
    "\n========================================================================"
#endif
    "\n";

int sha256_basic_example() {
#if defined(PRINT_RESULTS)
    printf(
    "\n========================================================================\n"
    "Basic Sha256 Example:\n");
#endif

    // "Hello World"
    const uint8_t message[] = { 72, 101, 108, 108, 111, 32,
                                87, 111, 114, 108, 100 };

    //a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
    const uint8_t digest[] = { 165, 145, 166, 212,  11, 244,  32,  64,
                                74,   1,  23,  51, 207, 183, 177, 144,
                               214,  44, 101, 191,  11, 205, 163,  43,
                                87, 178, 119, 217, 173, 159,  20, 110 };

    uint8_t result[SHA256_DIGEST_LEN] = { 0 };

    sha256(message, sizeof(message), result);

#if defined(PRINT_RESULTS)
    PrintBytesResult(result, SHA256_DIGEST_LEN);
#endif

    return memcmp(result, digest, SHA256_DIGEST_LEN) == 0;
}

////////////////////////////////////////////////////////////////////////////////
static const char *short_success_label =
    "\nSha256 Short Message Tests Successful: %s"
#if defined(PRINT_RESULTS)
    "\n========================================================================"
#endif
    "\n";

int sha256_short_cases() {
#if defined(PRINT_RESULTS)
    printf(
    "\n========================================================================\n"
    "Short NIST Sha256 Test Vectors:\n");
#endif

    int i;
    for (i = 0; i < SHORT_MESSAGE_COUNT; ++i) {
        uint8_t result[SHA256_DIGEST_LEN] = { 0 };

        uint8_t *hexBytes = HexToBytes(short_message[i].seed);
        sha256(hexBytes, short_message[i].width / 8, result);
        free(hexBytes);

#if defined(PRINT_RESULTS)
        PrintBytesResult(result, SHA256_DIGEST_LEN);
#endif

        uint8_t *testBytes = HexToBytes(short_message[i].digest);
        const int matches = memcmp(result, testBytes, SHA256_DIGEST_LEN) == 0;
        free(testBytes);

        if (!matches) {
            goto result;
        }
    }

    result:
    return i == SHORT_MESSAGE_COUNT;
}

////////////////////////////////////////////////////////////////////////////////
static const char *long_success_label =
    "\nSha256 Long Message Tests Successful: %s"
#if defined(PRINT_RESULTS)
    "\n========================================================================"
#endif
    "\n";

int sha256_long_cases() {
#if defined(PRINT_RESULTS)
    printf(
    "\n========================================================================\n"
    "Long NIST Sha256 Test Vectors:\n");
#endif
    int i;
    for (i = 0; i < LONG_MESSAGE_COUNT; ++i) {
        uint8_t result[SHA256_DIGEST_LEN] = { 0 };

        uint8_t *hexBytes = HexToBytes(long_message[i].seed);
        sha256(hexBytes, long_message[i].width / 8, result);
        free(hexBytes);

#if defined(PRINT_RESULTS)
        PrintBytesResult(result, SHA256_DIGEST_LEN);
#endif

        uint8_t *testBytes = HexToBytes(long_message[i].digest);
        const int matches = memcmp(result, testBytes, SHA256_DIGEST_LEN) == 0;
        free(testBytes);

        if (!matches) {
            goto result;
        }
    }

    result:
    return i == LONG_MESSAGE_COUNT;
}

////////////////////////////////////////////////////////////////////////////////
int main() {
    printf(
    "\n========================================================================\n"
    "Running Sha256 Tests"
    "\n========================================================================\n");

    const int caseCount = 3;
    int result = 0;;

    result += sha256_basic_example();
    printf(example_success_label, result == 1 ? "true" : "false");

    result += sha256_short_cases();
    printf(short_success_label, result == 2 ? "true" : "false");

    result += sha256_long_cases();
    printf(long_success_label, result == 3 ? "true" : "false");

    printf(
    "\n========================================================================\n"
    "%d of %d Sha256 Tests Passed Successfully"
    "\n========================================================================\n\n",
    result,
    caseCount);

    return 0;
}
