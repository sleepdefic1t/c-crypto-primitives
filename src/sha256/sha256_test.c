/**
 * This file is part of Ark C Crypto Primitives.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sha256/sha256.h"

#include "sha256/fixtures/sha256_fixtures.h"

////////////////////////////////////////////////////////////////////////////////
// build and run with gcc:
// `gcc -I../ sha256.c sha256_test.c -o sha256`
// `./sha256`

// build and run with gcc, with result printing:
// `gcc -I../ sha256.c sha256_test.c -o sha256 -DPRINT_RESULTS`
// `./sha256`

////////////////////////////////////////////////////////////////////////////////
void BytesToHex(const uint8_t *buf, size_t len, char *out) {
    const uint8_t *it = buf;
    const char *hex = "0123456789abcdef";
    char *ptr = out;
    for(; it < buf + len; ptr += 2, ++it){
        ptr[0] = hex[(*it >> 4) & 0xF];
        ptr[1] = hex[ *it       & 0xF];
    }
}

////////////////////////////////////////////////////////////////////////////////
// Adapted from:
// - https://gist.github.com/xsleonard/7341172
//
// Caller must ensure resulting value is freed.
uint8_t* HexToBytes(const char* hexstr) {
    size_t len = strlen(hexstr);
    if (len % 2 != 0) {
        return NULL;
    }

    size_t final_len = len / 2;

    uint8_t* c = (uint8_t*)malloc((final_len + 1) * sizeof(*c));

    for (size_t i = 0, j = 0; j < final_len; i += 2, j++) {
        c[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
    }

    c[final_len] = '\0';

    return c;
}

////////////////////////////////////////////////////////////////////////////////
#if defined(PRINT_RESULTS)
    void printSha256Result(uint8_t *result) {
        char buffer[2 * SHA256_DIGEST_LEN + 1];
        memset(buffer, 0, 2 * SHA256_DIGEST_LEN + 1);
        BytesToHex(result, SHA256_DIGEST_LEN, buffer);
        printf("\nresult: %s", buffer);
    }
#endif

////////////////////////////////////////////////////////////////////////////////
static const char *example_success_label =
    "\nSha256 Basic Example Successful: %s"
#if defined(PRINT_RESULTS)
    "\n========================================================================"
#endif
    "\n";

bool sha256_basic_example() {
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
    printSha256Result(result);
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

bool sha256_short_cases() {
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
        printSha256Result(result);
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

bool sha256_long_cases() {
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
        printSha256Result(result);
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
