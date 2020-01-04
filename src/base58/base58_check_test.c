/**
 * This file is part of Ark C Crypto Primitives.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base58_check.h"

#include "base58/fixtures/base58_check_fixtures.h"

////////////////////////////////////////////////////////////////////////////////
// build and run with gcc:
// `gcc -I../ base58_check_test.c base58_check.c base58.c ../sha256/sha256.c -o base58_check`
// `./base58_check`

// build and run with gcc, with result printing:
// `gcc -I../ base58_check_test.c base58_check.c base58.c ../sha256/sha256.c -o base58_check -DPRINT_RESULTS`
// `./base58_check`

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
    void printBase58CheckResult(const char *result) {
        printf("\nresult: %s", result);
    }

    void printBase58CheckDecodeResult(uint8_t *result, size_t len) {
        char buffer[(len * 2) + 1];
        memset(buffer, 0, sizeof(buffer));
        BytesToHex(result, len, buffer);
        printBase58CheckResult(buffer);
    }
#endif

//////////////////////////////////////////////////////////////////////////////
static const char *check_encode_success_label =
        "\nBase58Check Encode Standard Tests Successful: %s"
#if defined(PRINT_RESULTS)
        "\n=============================================================="
#endif
        "\n";

int base58_check_encode_cases() {
#if defined(PRINT_RESULTS)
    printf("\n==============================================================\n"
           "\nBase58Check Encode Standard Test Vectors:\n");
#endif

    int i;
    for (i = 0; i < BASE58_CHECK_VECTOR_COUNT; ++i) {
        size_t resultLen =
                BASE58_ENCODED_LEN_GET(check_valid_vectors[i].hexLen * 2);
        char result[resultLen];
        memset(result, 0, resultLen);

        uint8_t *hexBytes = HexToBytes(check_valid_vectors[i].hex);
        base58CheckEncode(hexBytes,
                          check_valid_vectors[i].hexLen,
                          result,
                          &resultLen);
        free(hexBytes);

#if defined(PRINT_RESULTS)
        printBase58CheckResult(result);
#endif

        if (strcmp(result, check_valid_vectors[i].base58Check) != 0) {
            goto result;
        }
    }

    result:
    return i == BASE58_CHECK_VECTOR_COUNT;
}

//////////////////////////////////////////////////////////////////////////////
static const char *check_decode_success_label =
        "\nBase58Check Decode Standard Tests Successful: %s"
#if defined(PRINT_RESULTS)
        "\n========================================================="
#endif
        "\n";

int base58_check_decode_cases() {
#if defined(PRINT_RESULTS)
    printf("\n=========================================================\n"
           "\nBase58Check Decode Standard Test Vectors:\n");
#endif

    int i;
    for (i = 0; i < BASE58_CHECK_VECTOR_COUNT; ++i) {
        size_t resultLen =
                BASE58_DECODED_LEN_GET(check_valid_vectors[i].base58CheckLen);
        uint8_t result[resultLen];
        memset(result, 0, resultLen);

        base58CheckDecode(check_valid_vectors[i].base58Check,
                          check_valid_vectors[i].base58CheckLen,
                          result,
                          &resultLen);

#if defined(PRINT_RESULTS)
        printBase58CheckDecodeResult(result, resultLen - 4);
#endif

        uint8_t *hexBytes = HexToBytes(check_valid_vectors[i].hex);
        const int matches = memcmp(result,
                                   hexBytes,
                                   check_valid_vectors[i].hexLen) == 0;
        free(hexBytes);

        if (!matches) {
            goto result;
        }
    }

    result:
    return i == BASE58_CHECK_VECTOR_COUNT;
}

//////////////////////////////////////////////////////////////////////////////
static const char *check_invalid_success_label =
        "\nBase58Check Decode Invalid Tests Successful: %s"
#if defined(PRINT_RESULTS)
        "\n========================================================="
#endif
        "\n";

int base58_check_invalid_cases() {
#if defined(PRINT_RESULTS)
    printf("\n=========================================================\n"
           "\nBase58Check Decode Invalid Test Vectors:\n");
#endif

    int i;
    for (i = 0; i < BASE58_CHECK_INVALID_COUNT; ++i) {
        size_t resultLen =
                BASE58_DECODED_LEN_GET(check_invalid_vectors[i].base58CheckLen);
        uint8_t result[resultLen];

        if (base58CheckDecode(check_invalid_vectors[i].base58Check,
                          check_invalid_vectors[i].base58CheckLen,
                          result,
                          &resultLen) != 0) {
            goto result;
        }
    }

    result:
    return i == BASE58_CHECK_INVALID_COUNT;
}

//////////////////////////////////////////////////////////////////////////////
int main() {
    printf(
        "\n==============================================================\n"
        "Running Base58Check Tests"
        "\n==============================================================\n");

    const int caseCount = 3;
    int result = 0;

    result += base58_check_encode_cases();
    printf(check_encode_success_label, result == 1 ? "true" : "false");

    result += base58_check_decode_cases();
    printf(check_decode_success_label, result == 2 ? "true" : "false");

    result += base58_check_invalid_cases();
    printf(check_invalid_success_label, result == 3 ? "true" : "false");

    printf(
        "\n==============================================================\n"
        "%d of %d Base58Check Tests Passed Successfully"
        "\n==============================================================\n\n",
        result,
        caseCount);

    return 0;
}
