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
// #include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sha256.h"

#include "sha256_fixtures.h"

// build and run with gcc:
// `gcc sha256.c sha256_test.c -o sha256`
// `./sha256`

////////////////////////////////////////////////////////////////////////////////
void BytesToHex(const unsigned char *buf, size_t len, char *out) {
    const unsigned char *it = buf;
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
unsigned char* HexToBytes(const char* hexstr) {
    size_t len = strlen(hexstr);
    if(len % 2 != 0) {
        return NULL;
    }

    size_t final_len = len / 2;

    unsigned char* c = (unsigned char*)malloc((final_len + 1) * sizeof(*c));

    for (size_t i = 0, j = 0; j < final_len; i += 2, j++) {
        c[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
    }

    c[final_len] = '\0';

    return c;
}

////////////////////////////////////////////////////////////////////////////////
void printSha256Result(unsigned char *result) {
    char buffer[2 * SHA256_DIGEST_LEN] = { 0 };
    BytesToHex(result, SHA256_DIGEST_LEN, buffer);
    printf("\nresult: %s", buffer);
}

////////////////////////////////////////////////////////////////////////////////
static const char *example_success_label =
"\n\nSha256 Basic Example Successful: %s"
"\n========================================================================\n";

bool sha256_basic_example() {
    printf(
    "\n========================================================================\n"
    "Basic Sha256 Example:\n");

    // "Hello World"
    const unsigned char message[] = { 72, 101, 108, 108, 111, 32,
                                      87, 111, 114, 108, 100 };

    //a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
    const unsigned char digest[] = { 165, 145, 166, 212,  11, 244,  32,  64,
                                      74,   1,  23,  51, 207, 183, 177, 144,
                                     214,  44, 101, 191,  11, 205, 163,  43,
                                      87, 178, 119, 217, 173, 159,  20, 110 };

    unsigned char result[SHA256_DIGEST_LEN] = { 0 };

    sha256(message, sizeof(message), result);

    printSha256Result(result);

    return memcmp(result, digest, SHA256_DIGEST_LEN) == 0;
}

////////////////////////////////////////////////////////////////////////////////
static const char *short_success_label =
"\n\nSha256 Short Message Tests Successful: %s"
"\n========================================================================\n";

bool sha256_short_cases() {
    printf(
    "\n========================================================================\n"
    "Short NIST Sha256 Test Vectors:\n");

    int i;
    for (i = 0; i < SHORT_MESSAGE_COUNT; ++i) {
        unsigned char result[SHA256_DIGEST_LEN] = { 0 };

        sha256(HexToBytes(short_message[i].seed), short_message[i].width / 8, result);

        printSha256Result(result);

        if (memcmp(result, HexToBytes(short_message[i].digest), SHA256_DIGEST_LEN) != 0) {
            goto result;
        }
    }

    result:
    return i == SHORT_MESSAGE_COUNT;
}

////////////////////////////////////////////////////////////////////////////////
static const char *long_success_label =
"\n\nSha256 Long Message Tests Successful: %s"
"\n========================================================================\n";

bool sha256_long_cases() {
    printf(
    "\n========================================================================\n"
    "Long NIST Sha256 Test Vectors:\n");

    int i;
    for (i = 0; i < LONG_MESSAGE_COUNT; ++i) {
        unsigned char result[SHA256_DIGEST_LEN] = { 0 };

        sha256(HexToBytes(long_message[i].seed), long_message[i].width / 8, result);

        printSha256Result(result);

        if (memcmp(result, HexToBytes(long_message[i].digest), SHA256_DIGEST_LEN) != 0) {
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
