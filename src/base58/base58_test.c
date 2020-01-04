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

#include "base58/base58.h"

#include "base58/fixtures/base58_fixtures.h"

////////////////////////////////////////////////////////////////////////////////
// build and run with gcc:
// `gcc -I../ base58_test.c base58.c -o base58`
// `./base58`

// build and run with gcc, with result printing:
// `gcc -I../ base58_test.c base58.c -o base58 -DPRINT_RESULTS`
// `./base58`

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
    void printBase58Result(const char *result) {
        printf("\nresult: %s", result);
    }

    void printBase58DecodeResult(uint8_t *result, size_t len) {
        // char buffer[BASE58_VECTOR_HEX_MAX + 1] = { '\0' };
        char buffer[(len * 2) + 1];
        memset(buffer, 0, sizeof(buffer));
        BytesToHex(result, len, buffer);
        printBase58Result(buffer);
    }
#endif

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
        printBase58Result(result);
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
        printBase58DecodeResult(result, resultLen);
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
