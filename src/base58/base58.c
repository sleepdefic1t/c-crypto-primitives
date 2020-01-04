/**
 * This file is part of Ark C Crypto Primitives.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 * 
 * 
 * Adapted from: https://github.com/bcoin-org/bcrypto/
 * 
 * Copyright (c) 2017-2019, Christopher Jeffrey (https://github.com/chjj)
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 * 
 * Changes:
 * - remove dynamic allocation.
 * - add constants/remove magic numbers.
 * - rearrange method args to better reflect intent.
 *   (e.g. encode data / decode string)
 * - add macros to calculate encode/decode output size.
 **/

#include "base58.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

////////////////////////////////////////////////////////////////////////////////
// Constants
#define BASE58_CHARSET_LEN      58
#define BASE58_TABLE_LEN        128
#define BASE58_BIT_MULTIPLIER   256

#define ASCII_CONTROL_FLAG      0x80

#define BASE58_ENCODE_MAX_LEN   1073741823UL    // 2^30 - 1
#define BASE58_DECODE_MAX_LEN   1481763716UL    // (2^30 - 1) * 138 / 100 + 1

static const char *BASE58_CHARSET = "123456789"
                                    "ABCDEFGHJKLMNPQRSTUVWXYZ"
                                    "abcdefghijkmnopqrstuvwxyz";

static const int BASE58_TABLE[BASE58_TABLE_LEN] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
  -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
  22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
  -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
  47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1
};

////////////////////////////////////////////////////////////////////////////////
// Base58 Encode Hex-bytes.
//
// Dynamic allocation via `malloc` removed;
// this is particularly useful in embedded environments.
//
// Caller is responsible for ensuring destination is properly sized.
// (hint: Base58-encoded output is ~138% of the size of the source.)
//
// If the input size could be unknown,
// we can still use the following from the caller:
// | ------------------------------------------
// | size_t strLen = BASE58_ENCODED_LEN_GET(x);
// | char *str = (char *)malloc(strLen);
// | ------------------------------------------
//
// ---
int
base58Encode(const uint8_t *data, size_t dataLen, char *str, size_t *strLen) {
    if (data == NULL || str == NULL || strLen == NULL) {
        return 0;
    }

    if (dataLen > BASE58_ENCODE_MAX_LEN) {  
        return 0;
    }

    // Len of 0 is valid;
    // output will just be empty.
    if (dataLen == 0) {
        str[0] = '\0';
        *strLen = 0;

        return 1;
    }

    size_t zeroes = 0;
    size_t i;

    for (i = 0; i < dataLen; i++) {
        if (data[i] != 0) {
            break;
        }

        zeroes += 1;
    }

    size_t b58len = BASE58_ENCODED_LEN_GET(dataLen);

    if (*strLen < b58len) {
        str[0] = '\0';
        *strLen = 0;

        return 0;
    }

    uint8_t *b58 = (uint8_t *)str;
    memset(b58, 0, b58len);

    size_t length = 0;

    for (; i < dataLen; i++) {
        int carry = data[i];
        size_t j = 0;
        int64_t k;

        for (k = (int64_t)b58len - 1; k >= 0; k--, j++) {
            if (carry == 0 && j >= length) {
                break;
            }

            carry += BASE58_BIT_MULTIPLIER * b58[k];
            b58[k] = carry % BASE58_CHARSET_LEN;
            carry = carry / BASE58_CHARSET_LEN;
        }

        if (carry != 0) {
            return 0;
        }

        length = j;
    }

    i = b58len - length;

    while (i < b58len && b58[i] == 0) {
        i += 1;
    }

    size_t j;

    for (j = 0; j < zeroes; j++) {
        str[j] = '1';
    }

    for (; i < b58len; i++) {
        str[j++] = BASE58_CHARSET[b58[i]];
    }

    str[j] = '\0';
    *strLen = j;

    return 1;
}

////////////////////////////////////////////////////////////////////////////////
// Decode a Base58 string.
//
// Dynamic allocation via `malloc` removed;
// this is particularly useful in embedded environments.
//
// Caller is responsible for ensuring destination is properly sized.
// (hint: Base58-decoded output is ~73% of the size of the source.)
//
// If the input size could be unknown,
// we can still use the following from the caller:
// | ------------------------------------------
// | size_t dataLen = BASE58_DECODED_LEN_GET(x);
// | uint8_t *data = (char *)malloc(dataLen);
// | ------------------------------------------
//
// ---
int
base58Decode(const char *str, size_t strLen, uint8_t *data, size_t *dataLen) {
    if (str == NULL || data == NULL || dataLen == NULL) {
        return 0;
    }

    if (strLen > BASE58_DECODE_MAX_LEN) {
        return 0;
    } 

    // Len of 0 is valid;
    // output will just be empty.
    if (strLen == 0) {
        data[0] = '\0';
        *dataLen = 0;

        return 1;
    }

    size_t zeroes = 0;
    size_t i;

    for (i = 0; i < strLen; i++) {
        if (str[i] != '1') {
            break;
        }

        zeroes += 1;
    }

    size_t b256len = BASE58_DECODED_LEN_GET(strLen);

    if (*dataLen < b256len) {
        data[0] = '\0';
        *dataLen = 0;

        return 0;
    }

    uint8_t *b256 = data;
    memset(b256, 0, b256len);

    size_t length = 0;

    for (; i < strLen; i++) {
        uint8_t ch = (uint8_t)str[i];
        int v = (ch & ASCII_CONTROL_FLAG) ? -1 : BASE58_TABLE[ch];

        if (v == -1) {
            return 0;
        }

        int carry = v;
        size_t j = 0;
        int64_t k;

        for (k = (int64_t)b256len - 1; k >= 0; k--, j++) {
            if (carry == 0 && j >= length) {
                break;
            }

            carry += BASE58_CHARSET_LEN * b256[k];
            b256[k] = carry % BASE58_BIT_MULTIPLIER;
            carry = carry / BASE58_BIT_MULTIPLIER;
        }

        if (carry != 0) {
            return 0;
        }

        length = j;
    }

    i = 0;

    while (i < b256len && b256[i] == 0) {
        i += 1;
    }

    size_t j;

    for (j = 0; j < zeroes; j++) {
        data[j] = 0;
    }

    while (i < b256len) {
        data[j++] = b256[i++];
    }

    *dataLen = j;

    return 1;
}
