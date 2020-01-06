/**
 * This file is part of Ark C Crypto Primitives.
 *
 * (c) Ark Ecosystem <info@ark.io>
 * 
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 * 
 * 
 * Adapted from:
 * - https://github.com/openssl/openssl
 * - https://github.com/nayuki/Bitcoin-Cryptography-Library
 * 
 * openSSL
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 * 
 * 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 **/

#include "ripemd160.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

////////////////////////////////////////////////////////////////////////////////
// Constants
#include "rmdconst.h"

#define RIPEMD160_BLOCK_LEN     64
#define RIPEMD160_WORD_SIZE     (RIPEMD160_BLOCK_LEN / 4)
#define RIPEMD160_HWORD_SIZE    (RIPEMD160_WORD_SIZE / 2)

#define RIPEMD160_STATE_COUNT   5
#define RIPEMD160_ROUNDS        80

////////////////////////////////////////////////////////////////////////////////
// Ripemd160 Context Struct
//
// Adapted from:  https://github.com/openssl/openssl
typedef struct ripemd160_context_t {
    uint32_t        state[RIPEMD160_STATE_COUNT];
    uint8_t         data[RIPEMD160_BLOCK_LEN];
    uint32_t        num, len;
} RIPEMD160_CTX;

////////////////////////////////////////////////////////////////////////////////
// Utility Macros
#define ROTATE_L(x, n)  ((((x & 0xFFFFFFFFULL) << n ) |                        \
                          ((x & 0xFFFFFFFFULL) >> (32 - n))) & 0xFFFFFFFFUL)

#define unpack4LE(buf)  (((((buf)[3]) & 0xFFFFFFFF) << 24)  |   \
                         ((((buf)[2]) & 0xFFFF)     << 16)  |   \
                         ((((buf)[1]) & 0xFF)       << 8)   |   \
                          (((buf)[0]) & 0xFF))

////////////////////////////////////////////////////////////////////////////////
// Transformed F2 and F4 are courtesy of Wei Dai
//
// src: https://github.com/openssl/openssl
#define F1(x,y,z)       ((x) ^ (y) ^ (z))
#define F2(x,y,z)       ((((y) ^ (z)) & (x)) ^ (z))
#define F3(x,y,z)       (((~(y)) | (x)) ^ (z))
#define F4(x,y,z)       ((((x) ^ (y)) & (z)) ^ (y))
#define F5(x,y,z)       (((~(z)) | (y)) ^ (x))

// Adapted from: https://github.com/nayuki/Bitcoin-Cryptography-Library
// Copyright (c) Project Nayuki (MIT License)
//
// changes:
// - use openSSL transform macros.
uint64_t RIPEMD160_Transform(int i, uint64_t x, uint64_t y, uint64_t z) {
    switch (i >> 4) {
        case 0:  return F1(x,y,z);
        case 1:  return F2(x,y,z);
        case 2:  return F3(x,y,z);
        case 3:  return F4(x,y,z);
        case 4:  return F5(x,y,z);
        default:  return 0;
    }
}

////////////////////////////////////////////////////////////////////////////////
// Static initializers.
//
// Adapted from https://github.com/nayuki/Bitcoin-Cryptography-Library
// Copyright (c) Project Nayuki (MIT License)
//
// changes:
// - use openSSL constants.
const uint64_t KL[RIPEMD160_STATE_COUNT] = { KL0, KL1, KL2, KL3, KL4 };
const uint64_t KR[RIPEMD160_STATE_COUNT] = { KR0, KR1, KR2, KR3, KR4 };

const uint8_t WL[RIPEMD160_ROUNDS] = {
    WL00, WL01, WL02, WL03, WL04, WL05, WL06, WL07, WL08, WL09,
    WL10, WL11, WL12, WL13, WL14, WL15, WL16, WL17, WL18, WL19,
    WL20, WL21, WL22, WL23, WL24, WL25, WL26, WL27, WL28, WL29,
    WL30, WL31, WL32, WL33, WL34, WL35, WL36, WL37, WL38, WL39,
    WL40, WL41, WL42, WL43, WL44, WL45, WL46, WL47, WL48, WL49,
    WL50, WL51, WL52, WL53, WL54, WL55, WL56, WL57, WL58, WL59,
    WL60, WL61, WL62, WL63, WL64, WL65, WL66, WL67, WL68, WL69,
    WL70, WL71, WL72, WL73, WL74, WL75, WL76, WL77, WL78, WL79
};

const uint8_t SL[RIPEMD160_ROUNDS] = {
    SL00, SL01, SL02, SL03, SL04, SL05, SL06, SL07, SL08, SL09,
    SL10, SL11, SL12, SL13, SL14, SL15, SL16, SL17, SL18, SL19,
    SL20, SL21, SL22, SL23, SL24, SL25, SL26, SL27, SL28, SL29,
    SL30, SL31, SL32, SL33, SL34, SL35, SL36, SL37, SL38, SL39,
    SL40, SL41, SL42, SL43, SL44, SL45, SL46, SL47, SL48, SL49,
    SL50, SL51, SL52, SL53, SL54, SL55, SL56, SL57, SL58, SL59,
    SL60, SL61, SL62, SL63, SL64, SL65, SL66, SL67, SL68, SL69,
    SL70, SL71, SL72, SL73, SL74, SL75, SL76, SL77, SL78, SL79
};

const uint8_t WR[RIPEMD160_ROUNDS] = {
    WR00, WR01, WR02, WR03, WR04, WR05, WR06, WR07, WR08, WR09,
    WR10, WR11, WR12, WR13, WR14, WR15, WR16, WR17, WR18, WR19,
    WR20, WR21, WR22, WR23, WR24, WR25, WR26, WR27, WR28, WR29,
    WR30, WR31, WR32, WR33, WR34, WR35, WR36, WR37, WR38, WR39,
    WR40, WR41, WR42, WR43, WR44, WR45, WR46, WR47, WR48, WR49,
    WR50, WR51, WR52, WR53, WR54, WR55, WR56, WR57, WR58, WR59,
    WR60, WR61, WR62, WR63, WR64, WR65, WR66, WR67, WR68, WR69,
    WR70, WR71, WR72, WR73, WR74, WR75, WR76, WR77, WR78, WR79
};

const uint8_t SR[RIPEMD160_ROUNDS] = {
    SR00, SR01, SR02, SR03, SR04, SR05, SR06, SR07, SR08, SR09,
    SR10, SR11, SR12, SR13, SR14, SR15, SR16, SR17, SR18, SR19,
    SR20, SR21, SR22, SR23, SR24, SR25, SR26, SR27, SR28, SR29,
    SR30, SR31, SR32, SR33, SR34, SR35, SR36, SR37, SR38, SR39,
    SR40, SR41, SR42, SR43, SR44, SR45, SR46, SR47, SR48, SR49,
    SR50, SR51, SR52, SR53, SR54, SR55, SR56, SR57, SR58, SR59,
    SR60, SR61, SR62, SR63, SR64, SR65, SR66, SR67, SR68, SR69,
    SR70, SR71, SR72, SR73, SR74, SR75, SR76, SR77, SR78, SR79
};

////////////////////////////////////////////////////////////////////////////////
// Set the initial state.
//
// Adapted from: https://github.com/openssl/openssl
static void RIPEMD160_Init(RIPEMD160_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->state[0] = RIPEMD160_A;
    ctx->state[1] = RIPEMD160_B;
    ctx->state[2] = RIPEMD160_C;
    ctx->state[3] = RIPEMD160_D;
    ctx->state[4] = RIPEMD160_E;
}

////////////////////////////////////////////////////////////////////////////////
// Process/Compress the current data.
//
// Adapted from https://github.com/nayuki/Bitcoin-Cryptography-Library
// Copyright (c) Project Nayuki (MIT License)
//
// changes:
// - use RIPEMD160_CTX.
// - break up transform loop using additional locals for readability.
// - use patterns from openSSL.
void RIPEMD160_Process(RIPEMD160_CTX *ctx, const uint8_t *data, size_t len) {
    if (len % RIPEMD160_BLOCK_LEN != 0) {
        return;
    }

    uint64_t A, B, C, D, E;
    uint64_t a, b, c, d, e;

    uint32_t XX[RIPEMD160_WORD_SIZE];
    #define X(i)    XX[i]

    for (size_t i = 0; i < len; ) {
        for (int j = 0; j < RIPEMD160_WORD_SIZE; j++, i += 4) {
            X(j) = unpack4LE(&data[i]);
        }

        A = ctx->state[0], a = ctx->state[0];
        B = ctx->state[1], b = ctx->state[1];
        C = ctx->state[2], c = ctx->state[2];
        D = ctx->state[3], d = ctx->state[3];
        E = ctx->state[4], e = ctx->state[4];

        for (int j = 0; j < RIPEMD160_ROUNDS; j++) {
            uint64_t transform, rotation, temp;

            transform = RIPEMD160_Transform(j, B, C, D);
            rotation = ROTATE_L(A + transform + X(WL[j]) + KL[j >> 4], SL[j]);
            temp = rotation + E;
            A = E;
            E = D;
            D = ROTATE_L(C, 10);
            C = B;
            B = temp;

            transform = RIPEMD160_Transform(RIPEMD160_ROUNDS - 1 - j, b, c, d);
            rotation = ROTATE_L(a + transform + X(WR[j]) + KR[j >> 4], SR[j]);
            temp = rotation + e;
            a = e;
            e = d;
            d = ROTATE_L(c, 10);
            c = b;
            b = temp;
        }

        uint64_t temp = ctx->state[1] + C + d;
        ctx->state[1] = ctx->state[2] + D + e;
        ctx->state[2] = ctx->state[3] + E + a;
        ctx->state[3] = ctx->state[4] + A + b;
        ctx->state[4] = ctx->state[0] + B + c;
        ctx->state[0] = temp;
    }
}

////////////////////////////////////////////////////////////////////////////////
// Add data to be hashed.
static void RIPEMD160_Update(RIPEMD160_CTX *ctx, const void *data, size_t len) {
    if (data == NULL || len == 0) {
        return;
    }

    ctx->len = len;
    ctx->num = ctx->len & ~(RIPEMD160_BLOCK_LEN - 1);

    RIPEMD160_Process(ctx, data, ctx->num);
    memcpy(ctx->data, &data[ctx->num], ctx->len - ctx->num);
}

////////////////////////////////////////////////////////////////////////////////
// Finalize the Ripemd160 hash operation.
//
// Adapted from https://github.com/nayuki/Bitcoin-Cryptography-Library
// Copyright (c) Project Nayuki (MIT License)
//
// changes:
// - use RIPEMD160_CTX.
// - use openSSL constants.
// - extract state initialization.
void RIPEMD160_Final(RIPEMD160_CTX *ctx, uint8_t *digest) {
    if (digest == NULL) {
        return;
    }

    ctx->num = ctx->len & (RIPEMD160_BLOCK_LEN - 1);
    ctx->data[ctx->num] = 0x80;

    ctx->num++;

    if (ctx->num + RIPEMD160_HWORD_SIZE > RIPEMD160_BLOCK_LEN) {
        RIPEMD160_Process(ctx, ctx->data, RIPEMD160_BLOCK_LEN);
        memset(ctx->data, 0, RIPEMD160_BLOCK_LEN);
    }

    ctx->data[RIPEMD160_BLOCK_LEN - RIPEMD160_HWORD_SIZE] =
            (ctx->len & 0x1FU) << 3;
    ctx->len >>= RIPEMD160_STATE_COUNT;

    for (int i = 1;
         i < RIPEMD160_HWORD_SIZE; i++,
         ctx->len >>= RIPEMD160_HWORD_SIZE) {
        ctx->data[RIPEMD160_BLOCK_LEN - RIPEMD160_HWORD_SIZE + i] = ctx->len;
    }

    RIPEMD160_Process(ctx, ctx->data, RIPEMD160_BLOCK_LEN);

    for (int i = 0; i < RIPEMD160_DIGEST_LEN; i++) {
        digest[i] = (ctx->state[i >> 2] >> ((i & 3) << 3));
    }
}

////////////////////////////////////////////////////////////////////////////////
void ripemd160(const uint8_t *src, size_t len, uint8_t *digest) {
    RIPEMD160_CTX ctx;
    static uint8_t temp[RIPEMD160_DIGEST_LEN];

    if (digest == NULL) {
        digest = temp;
    }

    RIPEMD160_Init(&ctx);
    RIPEMD160_Update(&ctx, src, len);
    RIPEMD160_Final(&ctx, digest);

    memset(&ctx, 0, sizeof(ctx));
}
