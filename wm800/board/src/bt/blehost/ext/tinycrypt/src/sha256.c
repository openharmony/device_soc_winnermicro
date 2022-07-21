/* sha256.c - TinyCrypt SHA-256 crypto hash algorithm implementation */

/*
 *  Copyright (C) 2017 by Intel Corporation, All Rights Reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *    - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *    - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *    - Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/utils.h>

static void compress(unsigned int *iv, const uint8_t *data);

int tc_sha256_init(TCSha256State_t s)
{
    /* input sanity check: */
    if (s == (TCSha256State_t) 0) {
        return TC_CRYPTO_FAIL;
    }

    /*
     * Setting the initial state values.
     * These values correspond to the first 32 bits of the fractional parts
     * of the square roots of the first 8 primes: 2, 3, 5, 7, 11, 13, 17
     * and 19.
     */
    _set((uint8_t *) s, 0x00, sizeof(*s));
    s->iv[0] = 0x6a09e667;
    s->iv[1] = 0xbb67ae85;
    s->iv[2] = 0x3c6ef372; // 2:array element
    s->iv[3] = 0xa54ff53a; // 3:array element
    s->iv[4] = 0x510e527f; // 4:array element
    s->iv[5] = 0x9b05688c; // 5:array element
    s->iv[6] = 0x1f83d9ab; // 6:array element
    s->iv[7] = 0x5be0cd19; // 7:array element
    return TC_CRYPTO_SUCCESS;
}

int tc_sha256_update(TCSha256State_t s, const uint8_t *data, size_t datalen)
{
    /* input sanity check: */
    if (s == (TCSha256State_t) 0 ||
            data == (void *) 0) {
        return TC_CRYPTO_FAIL;
    } else if (datalen == 0) {
        return TC_CRYPTO_SUCCESS;
    }

    while (datalen-- > 0) {
        s->leftover[s->leftover_offset++] = *(data++);

        if (s->leftover_offset >= TC_SHA256_BLOCK_SIZE) {
            compress(s->iv, s->leftover);
            s->leftover_offset = 0;
            s->bits_hashed += (TC_SHA256_BLOCK_SIZE << 3); // 3:byte alignment
        }
    }

    return TC_CRYPTO_SUCCESS;
}

int tc_sha256_final(uint8_t *digest, TCSha256State_t s)
{
    unsigned int i;

    /* input sanity check: */
    if (digest == (uint8_t *) 0 ||
            s == (TCSha256State_t) 0) {
        return TC_CRYPTO_FAIL;
    }

    s->bits_hashed += (s->leftover_offset << 3); // 3:byte alignment
    s->leftover[s->leftover_offset++] = 0x80; /* always room for one byte */

    if (s->leftover_offset > (sizeof(s->leftover) - 8)) { // 8:byte alignment
        /* there is not room for all the padding in this block */
        _set(s->leftover + s->leftover_offset, 0x00,
             sizeof(s->leftover) - s->leftover_offset);
        compress(s->iv, s->leftover);
        s->leftover_offset = 0;
    }

    /* add the padding and the length in big-Endian format */
    _set(s->leftover + s->leftover_offset, 0x00,
         sizeof(s->leftover) - 8 - s->leftover_offset); // 8:byte alignment
    s->leftover[sizeof(s->leftover) - 1] = (uint8_t)(s->bits_hashed);
    s->leftover[sizeof(s->leftover) - 2] = (uint8_t)(s->bits_hashed >> 8); // 2:byte alignment, 8:byte alignment
    s->leftover[sizeof(s->leftover) - 3] = (uint8_t)(s->bits_hashed >> 16); // 3:byte alignment, 16:byte alignment
    s->leftover[sizeof(s->leftover) - 4] = (uint8_t)(s->bits_hashed >> 24); // 4:byte alignment, 24:byte alignment
    s->leftover[sizeof(s->leftover) - 5] = (uint8_t)(s->bits_hashed >> 32); // 5:byte alignment, 32:byte alignment
    s->leftover[sizeof(s->leftover) - 6] = (uint8_t)(s->bits_hashed >> 40); // 6:byte alignment, 40:byte alignment
    s->leftover[sizeof(s->leftover) - 7] = (uint8_t)(s->bits_hashed >> 48); // 7:byte alignment, 48:byte alignment
    s->leftover[sizeof(s->leftover) - 8] = (uint8_t)(s->bits_hashed >> 56); // 8:byte alignment, 56:byte alignment
    /* hash the padding and length */
    compress(s->iv, s->leftover);

    /* copy the iv out to digest */
    for (i = 0; i < TC_SHA256_STATE_BLOCKS; ++i) {
        unsigned int t = *((unsigned int *) &s->iv[i]);
        *digest++ = (uint8_t)(t >> 24); // 24:byte alignment
        *digest++ = (uint8_t)(t >> 16); // 16:byte alignment
        *digest++ = (uint8_t)(t >> 8); // 8:byte alignment
        *digest++ = (uint8_t)(t);
    }

    /* destroy the current state */
    _set(s, 0, sizeof(*s));
    return TC_CRYPTO_SUCCESS;
}

/*
 * Initializing SHA-256 Hash constant words K.
 * These values correspond to the first 32 bits of the fractional parts of the
 * cube roots of the first 64 primes between 2 and 311.
 */
static const unsigned int k256[64] = { // 64:array length
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline unsigned int ROTR(unsigned int a, unsigned int n)
{
    return (((a) >> n) | ((a) << (32 - n))); // 32:byte alignment
}

#define Sigma0(a)(ROTR((a), 2) ^ ROTR((a), 13) ^ ROTR((a), 22))
#define Sigma1(a)(ROTR((a), 6) ^ ROTR((a), 11) ^ ROTR((a), 25))
#define sigma0(a)(ROTR((a), 7) ^ ROTR((a), 18) ^ ((a) >> 3))
#define sigma1(a)(ROTR((a), 17) ^ ROTR((a), 19) ^ ((a) >> 10))

#define Ch(a, b, c)(((a) & (b)) ^ ((~(a)) & (c)))
#define Maj(a, b, c)(((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))

static inline unsigned int BigEndian(const uint8_t **c)
{
    unsigned int n = 0;
    n = (((unsigned int)(*((*c)++))) << 24); // 24:byte alignment
    n |= ((unsigned int)(*((*c)++)) << 16); // 16:byte alignment
    n |= ((unsigned int)(*((*c)++)) << 8); // 8:byte alignment
    n |= ((unsigned int)(*((*c)++)));
    return n;
}

static void compress(unsigned int *iv, const uint8_t *data)
{
    unsigned int a, b, c, d, e, f, g, h;
    unsigned int t1, t2;
    unsigned int work_space[16];
    unsigned int i;
    a = iv[0];
    b = iv[1];
    c = iv[2]; // 2:array element
    d = iv[3]; // 3:array element
    e = iv[4]; // 4:array element
    f = iv[5]; // 5:array element
    g = iv[6]; // 6:array element
    h = iv[7]; // 7:array element
    
    for (i = 0; i < 16; ++i) { // 16:loop cap
        unsigned int n = BigEndian(&data);
        t1 = work_space[i] = n;
        t1 += h + Sigma1(e) + Ch(e, f, g) + k256[i];
        t2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    for (; i < 64; ++i) { // 64:loop cap
        unsigned int s0, s1;
        s0 = work_space[(i + 1) & 0x0f];
        s0 = sigma0(s0);
        s1 = work_space[(i + 14) & 0x0f]; // 14:array element
        s1 = sigma1(s1);
        t1 = work_space[i & 0xf] += s0 + s1 + work_space[(i + 9) & 0xf]; // 9:array element
        t1 += h + Sigma1(e) + Ch(e, f, g) + k256[i];
        t2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    iv[0] += a;
    iv[1] += b;
    iv[2] += c; // 2:array element
    iv[3] += d; // 3:array element
    iv[4] += e; // 4:array element
    iv[5] += f; // 5:array element
    iv[6] += g; // 6:array element
    iv[7] += h; // 7:array element
}