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
#include <stdio.h>
#include <string.h>

#include "ripemd160.h"

#include "ripemd160_fixtures.h"

// build and run with gcc:
// `gcc ripemd160.c ripemd160_test.c -o ripemd160`
// `./ripemd160`

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
// Adapted from:
// - https://www.includehelp.com/c/convert-ascii-string-to-byte-array-in-c.aspx
unsigned char*  AsciiToBytes(char* input){
    size_t len = strlen(input);

    unsigned char* c = (unsigned char*)malloc((len + 1) * sizeof(*c));

    int loop = 0;
    int i = 0;

    while(input[loop] != 0) {
        c[i++] = input[loop++];
    }

    c[len] = '\0';
    return c;
}

////////////////////////////////////////////////////////////////////////////////
void printRipemd160Result(unsigned char *result) {
    char buffer[2 * RIPEMD160_DIGEST_LEN + 1] = { 0 };
    BytesToHex(result, RIPEMD160_DIGEST_LEN, buffer);
    printf("\nresult: %s", buffer);
}

////////////////////////////////////////////////////////////////////////////////
static const char *standard_success_label =
        "\n\nRipemd160 Standard Tests Successful: %s"
        "\n================================================\n";

bool ripemd160_standard_cases() {
    printf("\n================================================\n"
           "Ripemd160 Standard Test Vectors:\n");

    int i;
    for (i = 0; i < STANDARD_VECTOR_COUNT; ++i) {
        unsigned char result[RIPEMD160_DIGEST_LEN] = { 0 };

        ripemd160(AsciiToBytes(standard_vectors[i].seed),
                  standard_vectors[i].size,
                  result);

        printRipemd160Result(result);

        if (memcmp(result,
                   HexToBytes(standard_vectors[i].digest),
                   RIPEMD160_DIGEST_LEN) != 0) {
            goto result;
        }
    }

    result:
    return i == STANDARD_VECTOR_COUNT;
}

////////////////////////////////////////////////////////////////////////////////
static const char *mismatch_success_label =
        "\n\nRipemd160 Mismatch Tests Successful: %s"
        "\n================================================\n";

bool ripemd160_mismatch_cases() {
    printf("\n================================================\n"
           "Ripemd160 Mismatch Test Vectors:\n");

    int i;
    for (i = 0; i < MISMATCH_VECTOR_COUNT; ++i) {
        unsigned char result[RIPEMD160_DIGEST_LEN] = { 0 };

        ripemd160(AsciiToBytes(mismatch_vectors[i].seed),
                  mismatch_vectors[i].size,
                  result);

        printRipemd160Result(result);

        // Mismatch cases should not match
        if (memcmp(result,
                   HexToBytes(mismatch_vectors[i].digest),
                   RIPEMD160_DIGEST_LEN) == 0) {
            goto result;
        }
    }

    result:
    return i == MISMATCH_VECTOR_COUNT;
}

////////////////////////////////////////////////////////////////////////////////
static const char *random_success_label =
        "\n\nRipemd160 Random Tests Successful: %s"
        "\n================================================\n";

bool ripemd160_random_cases() {
    printf("\n================================================\n"
           "Ripemd160 Random Test Vectors:\n");

    int i;
    for (i = 0; i < RANDOM_VECTOR_COUNT; ++i) {
        unsigned char result[RIPEMD160_DIGEST_LEN] = { 0 };

        ripemd160(AsciiToBytes(random_vectors[i].seed),
                  random_vectors[i].size,
                  result);

        printRipemd160Result(result);

        if (memcmp(result,
                   HexToBytes(random_vectors[i].digest),
                   RIPEMD160_DIGEST_LEN) != 0) {
            goto result;
        }
    }

    result:
    return i == RANDOM_VECTOR_COUNT;
}

////////////////////////////////////////////////////////////////////////////////
static const char *binary_success_label =
        "\n\nRipemd160 Binary Tests Successful: %s"
        "\n================================================\n";

bool ripemd160_binary_cases() {
    printf("\n================================================\n"
           "Ripemd160 Binary Test Vectors:\n");

    int i;
    for (i = 0; i < BINARY_VECTOR_COUNT; ++i) {
        unsigned char result[RIPEMD160_DIGEST_LEN] = { 0 };

        ripemd160(HexToBytes(binary_vectors[i].seed),
                  binary_vectors[i].size,
                  result);

        printRipemd160Result(result);

        if (memcmp(result,
                   HexToBytes(binary_vectors[i].digest),
                   RIPEMD160_DIGEST_LEN) != 0) {
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
