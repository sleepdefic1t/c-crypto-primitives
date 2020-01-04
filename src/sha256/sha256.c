/**
 * This file is part of Ark C Crypto Primitives.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 * 
 * 
 * Adapted from: https://github.com/openssl/openssl
 * Copyright 2004-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 **/

#include "sha256.h"

#include <stddef.h>
#include <string.h>

////////////////////////////////////////////////////////////////////////////////
// Constants
#define SHA256_WORD_SIZE    8
#define SHA256_BLOCK_LEN    64

////////////////////////////////////////////////////////////////////////////////
// Sha256 Context Struct
typedef struct {
    unsigned int h[SHA256_WORD_SIZE];       // state
    unsigned int lo, hi;                    // number of hi/lo bits processed
    unsigned char data[SHA256_BLOCK_LEN];   // buffer
    unsigned int num;                       // bits hashed count
} SHA256_CTX;

////////////////////////////////////////////////////////////////////////////////
// Hash Map of Sha256 Round Constants
// First 32 bits of the fractional parts of the cube roots
// of the first 64 primes 2..311
static const unsigned long SHA256_MAP[SHA256_BLOCK_LEN] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
    0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
    0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
    0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
    0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
    0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
    0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
    0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
    0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
    0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

////////////////////////////////////////////////////////////////////////////////
// Utility Macros
#define ROTATE(x, n)  ((((x & 0xFFFFFFFFUL) >> n ) |                        \
                        ((x & 0xFFFFFFFFUL) << (32 - n))) & 0xFFFFFFFFUL)

#define Sigma0(x) (ROTATE(x, 2)  ^ ROTATE(x, 13) ^ ROTATE(x, 22))
#define Sigma1(x) (ROTATE(x, 6)  ^ ROTATE(x, 11) ^ ROTATE(x, 25))
#define Gamma0(x) (ROTATE(x, 7)  ^ ROTATE(x, 18) ^ ((x) & 0xFFFFFFFFUL) >> (3))
#define Gamma1(x) (ROTATE(x, 17) ^ ROTATE(x, 19) ^ ((x) & 0xFFFFFFFFUL) >> (10))

#define Ch(x,y,z)    (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)   (((x) & (y)) ^   ((x)  & (z)) ^ ((y) & (z)))

#define RND(a,b,c,d,e,f,g,h,i)                                  \
     t0 = h + Sigma1(e) + Ch(e, f, g) + SHA256_MAP[i] + W[i];   \
     t1 = Sigma0(a) + Maj(a, b, c);                             \
     d += t0;                                                   \
     h  = t0 + t1;

// Big-endian Pack a 4-Byte value to a byte-buffer.
#define pack4BE(buf, value) {               \
    (buf)[0] = ((value) >> 24)  & 0xFF;     \
    (buf)[1] = ((value) >> 16)  & 0xFF;     \
    (buf)[2] = ((value) >> 8)   & 0xFF;     \
    (buf)[3] = ((value))        & 0xFF;     \
}

// Unpack a 4-Byte Big-endian-packed byte-buffer.
#define unpack4BE(buf)  (((((buf)[0]) & 0xFFFFFFFF) << 24)  |   \
                         ((((buf)[1]) & 0xFFFF)     << 16)  |   \
                         ((((buf)[2]) & 0xFF)       << 8)   |   \
                          (((buf)[3]) & 0xFF))

////////////////////////////////////////////////////////////////////////////////
// Process/Compress the current chunked bits
static void SHA256_Process(SHA256_CTX *ctx, const void *data) {
    unsigned long S0, S1, S2, S3, S4, S5, S6, S7,
                  W[SHA256_BLOCK_LEN],
                  t0, t1, t;
    int i;
    const unsigned char *ptr;

    // Copy the initial Sha state.
    S0 = ctx->h[0];
    S1 = ctx->h[1];
    S2 = ctx->h[2];
    S3 = ctx->h[3];
    S4 = ctx->h[4];
    S5 = ctx->h[5];
    S6 = ctx->h[6];
    S7 = ctx->h[7];

    ptr = data;
    for (i = 0; i < 2 * SHA256_WORD_SIZE; i++) {
        W[i] = unpack4BE(ptr);
        ptr += 4;
    }

    for (i = 2 * SHA256_WORD_SIZE; i < SHA256_BLOCK_LEN; i++) {
        W[i] = Gamma1(W[i - 2]) +
                      W[i - 7] +
               Gamma0(W[i - 15]) +
                      W[i - 16];
    }

    for (i = 0; i < SHA256_BLOCK_LEN; ++i) {
        RND(S0, S1, S2, S3, S4, S5, S6, S7, i);
        t = S7;
        S7 = S6;
        S6 = S5;
        S5 = S4; 
        S4 = S3;
        S3 = S2;
        S2 = S1;
        S1 = S0;
        S0 = t;
    }
 
    ctx->h[0] += S0;
    ctx->h[1] += S1;
    ctx->h[2] += S2;
    ctx->h[3] += S3;
    ctx->h[4] += S4;
    ctx->h[5] += S5;
    ctx->h[6] += S6;
    ctx->h[7] += S7;
}

////////////////////////////////////////////////////////////////////////////////
// Initialize a Sha256 Context.
// Sets the initial Sha256 state.
// First 32 bits of the fractional parts of the square roots
// of the first 8 primes 2..19
static void SHA256_Init(SHA256_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->h[0] = 0x6a09e667UL;
    ctx->h[1] = 0xbb67ae85UL;
    ctx->h[2] = 0x3c6ef372UL;
    ctx->h[3] = 0xa54ff53aUL;
    ctx->h[4] = 0x510e527fUL;
    ctx->h[5] = 0x9b05688cUL;
    ctx->h[6] = 0x1f83d9abUL;
    ctx->h[7] = 0x5be0cd19UL;
}

////////////////////////////////////////////////////////////////////////////////
// Add data to be hashed.
static void SHA256_Update(SHA256_CTX *ctx, const void *src, unsigned int len) {
    unsigned count = (ctx->lo + (len << 3)) & 0xffffffff;

    if (count < ctx->lo) {
        ctx->hi += 1;
    }

    ctx->lo = count;

    while (len) {
        unsigned int step = SHA256_BLOCK_LEN - ctx->num;

        if (step > len) {
            step = len;
        }

        memcpy(ctx->data + ctx->num, src, step);

        if (step + ctx->num < SHA256_BLOCK_LEN) {
            ctx->num += step;
            break;
        }

        src = (const unsigned char *)src + step;
        len -= step;
        ctx->num = 0;

        SHA256_Process(ctx, ctx->data);
    }
}

////////////////////////////////////////////////////////////////////////////////
// Finalize the Sha256 hash operation.
static void SHA256_Final(SHA256_CTX *ctx, unsigned char *digest){
    unsigned int i;
    unsigned char final[SHA256_WORD_SIZE];

    pack4BE(&final[0], ctx->hi);
    pack4BE(&final[4], ctx->lo);

    SHA256_Update(ctx, "\200", 1);

    if (ctx->num > SHA256_BLOCK_LEN - SHA256_WORD_SIZE) {
        SHA256_Update(ctx, "\0\0\0\0\0\0\0\0", SHA256_WORD_SIZE);
    }

    memset(ctx->data + ctx->num,
           0,
           SHA256_BLOCK_LEN - SHA256_WORD_SIZE - ctx->num);

    ctx->num = SHA256_BLOCK_LEN - SHA256_WORD_SIZE;

    SHA256_Update(ctx, final, SHA256_WORD_SIZE);

    for (i = 0; i < SHA256_WORD_SIZE; i++) {
        pack4BE(digest + 4 * i, ctx->h[i]);
    }

    memset(ctx, 0, sizeof(*ctx));
}

////////////////////////////////////////////////////////////////////////////////
// Public Convenience Method
void sha256(const unsigned char *src, size_t len, unsigned char *digest) {
    SHA256_CTX ctx;
    static unsigned char temp[SHA256_DIGEST_LEN];

    if (digest == NULL) {
        digest = temp;
    }

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, src, len);
    SHA256_Final(&ctx, digest);

    memset(&ctx, 0, sizeof(ctx));
}