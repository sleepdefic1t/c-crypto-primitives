/**
 * This file is part of Ark C Crypto Primitives.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#include "base58/base58_check.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "base58/base58.h"

#include "sha256/sha256.h"

////////////////////////////////////////////////////////////////////////////////
// Constants
#define BASE58_CHECKSUM_LEN 4

////////////////////////////////////////////////////////////////////////////////
// Base58 Encode data, appendinga a 4-byte checksum to the result.
int base58CheckEncode(const uint8_t *data,
                      size_t dataLen,
                      char *str,
                      size_t *strLen) {
    if (data == NULL || str == NULL || strLen == NULL) {
        return 0;
    }

    const size_t finalLen = dataLen + BASE58_CHECKSUM_LEN;

    if (finalLen > *strLen) {
        str[0] = '\0';
        *strLen = 0;

        return 0;
    }

    uint8_t temp[finalLen];
    uint8_t checksum[SHA256_DIGEST_LEN];

    memcpy(temp, data, dataLen);

    // Calculate the checksum and append its first 4 bytes to the output.
    sha256(temp, dataLen, checksum);
    sha256(checksum, SHA256_DIGEST_LEN, checksum);

    memcpy(&temp[dataLen], checksum, BASE58_CHECKSUM_LEN);

    memset(checksum, 0, SHA256_DIGEST_LEN);

    if (base58Encode(temp, finalLen, str, strLen) == 0) {
        memset(temp, 0, finalLen);
        memset(str, 0, *strLen);

        return 0;
    }

    memset(temp, 0, finalLen);

    return 1;
}

////////////////////////////////////////////////////////////////////////////////
// Decode a Base58Check-encoded string and verify its 4-byte checksum.
int base58CheckDecode(const char *str,
                      size_t strLen,
                      uint8_t *data,
                      size_t *dataLen) {
    if (str == NULL || data == NULL || dataLen == NULL) {
        return 0;
    }

    uint8_t temp[*dataLen];
    uint8_t checksum[SHA256_DIGEST_LEN];
    memset(temp, 0, *dataLen);

    if (base58Decode(str, strLen, temp, dataLen) == 0) {
        memset(temp, 0, *dataLen);
        memset(data, 0, *dataLen);

        return 0;
    }

    size_t copySize = *dataLen - BASE58_CHECKSUM_LEN;

    memcpy(data, temp, copySize);

    // Recalculate the checksum and verify its first 4-bytes.
    sha256(temp, *dataLen - BASE58_CHECKSUM_LEN, checksum);
    sha256(checksum, SHA256_DIGEST_LEN, checksum);

    if (memcmp(&temp[copySize], checksum, BASE58_CHECKSUM_LEN) != 0) {
        memset(data, 0, copySize);
        return 0;
    }

    memset(temp, 0, *dataLen);
    memset(checksum, 0, SHA256_DIGEST_LEN);

    return 1;
}
