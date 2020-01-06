/**
 * This file is part of Ark C Crypto Primitives.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#ifndef ARK_CRYPTO_C_PRIMITIVES_TEST_HELPERS_H
#define ARK_CRYPTO_C_PRIMITIVES_TEST_HELPERS_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
// Adapted from:
// - https://www.includehelp.com/c/convert-ascii-string-to-byte-array-in-c.aspx
//
// Caller must ensure resulting value is freed.
uint8_t*  AsciiToBytes(const char* input){
    size_t len = strlen(input);

    uint8_t* c = (uint8_t*)malloc((len + 1) * sizeof(*c));

    int loop = 0;
    int i = 0;

    while(input[loop] != 0) {
        c[i++] = input[loop++];
    }

    c[len] = '\0';
    return c;
}

////////////////////////////////////////////////////////////////////////////////

#if defined(PRINT_RESULTS)

#include <stdio.h>

void PrintResult(const char *result) {
    printf("\nresult: %s", result);
}

void PrintBytesResult(uint8_t *result, size_t len) {
    char buffer[(len * 2) + 1];
    memset(buffer, 0, sizeof(buffer));

    BytesToHex(result, len, buffer);
    PrintResult(buffer);
}

#endif  // #if defined(PRINT_RESULTS)

#endif  // #define ARK_CRYPTO_C_PRIMITIVES_TEST_HELPERS_H
