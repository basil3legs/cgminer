/*
 * FIPS 180-2 SHA-224/256/384/512 implementation
 * Last update: 02/02/2007
 * Issue date:  04/30/2005
 *
 * Copyright (C) 2013, Con Kolivas <kernel@kolivas.org>
 * Copyright (C) 2005, 2007 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <string.h>

#include "sha2.h"

#define UNPACK32(x, str)                      \
{                                             \
    *((str) + 3) = (uint8_t) ((x)      );       \
    *((str) + 2) = (uint8_t) ((x) >>  8);       \
    *((str) + 1) = (uint8_t) ((x) >> 16);       \
    *((str) + 0) = (uint8_t) ((x) >> 24);       \
}

#define PACK32(str, x)                        \
{                                             \
    *(x) =   ((uint32_t) *((str) + 3)      )    \
           | ((uint32_t) *((str) + 2) <<  8)    \
           | ((uint32_t) *((str) + 1) << 16)    \
           | ((uint32_t) *((str) + 0) << 24);   \
}

#define SHA256_SCR(i)                         \
{                                             \
    w[i] =  SHA256_F4(w[i -  2]) + w[i -  7]  \
          + SHA256_F3(w[i - 15]) + w[i - 16]; \
}

uint32_t sha256_h0[8] =
            {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

uint32_t sha256_k[64] =
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
             0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
             0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
             0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/* SHA-256 functions */

void sha256_transf(sha256_ctx *ctx, const unsigned char *message,
                   unsigned int block_nb)
{
    uint32_t w[64];
    uint32_t wv[8];
    uint32_t t1, t2;
    const unsigned char *sub_block;
    int i;

    int j;

    for (i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 6);

        for (j = 0; j < 16; j++) {
            PACK32(&sub_block[j << 2], &w[j]);
        }

        for (j = 16; j < 64; j++) {
            SHA256_SCR(j);
        }

        for (j = 0; j < 8; j++) {
            wv[j] = ctx->h[j];
        }

		t1 = ctx->h[7] + SHA256_F2(ctx->h[4]) + CH(ctx->h[4], ctx->h[5], ctx->h[6]) + sha256_k[0] + w[0];
		t2 = SHA256_F1(ctx->h[0]) + MAJ(ctx->h[0], ctx->h[1], ctx->h[2]);
		wv[3] = ctx->h[3] + t1;
		wv[7] = t1 + t2;

		t1 = ctx->h[6] + SHA256_F2(wv[3]) + CH(wv[3], ctx->h[4], ctx->h[5]) + sha256_k[1] + w[1];
		t2 = SHA256_F1(wv[7]) + MAJ(wv[7], ctx->h[0], ctx->h[1]);
		wv[2] = ctx->h[2] + t1;
		wv[6] = t1 + t2;

		t1 = ctx->h[5] + SHA256_F2(wv[2]) + CH(wv[2], wv[3], ctx->h[4]) + sha256_k[2] + w[2];
		t2 = SHA256_F1(wv[6]) + MAJ(wv[6], wv[7], ctx->h[0]);
		wv[1] = ctx->h[1] + t1;
		wv[5] = t1 + t2;

		t1 = ctx->h[4] + SHA256_F2(wv[1]) + CH(wv[1], wv[2], wv[3]) + sha256_k[3] + w[3];
		t2 = SHA256_F1(wv[5]) + MAJ(wv[5], wv[6], wv[7]);
		wv[0] = ctx->h[0] + t1;
		wv[4] = t1 + t2;

		t1 = wv[3] + SHA256_F2(wv[0]) + CH(wv[0], wv[1], wv[2]) + sha256_k[4] + w[4];
		t2 = SHA256_F1(wv[4]) + MAJ(wv[4], wv[5], wv[6]);
		wv[7] = wv[7] + t1;
		wv[3] = t1 + t2;

		t1 = wv[2] + SHA256_F2(wv[7]) + CH(wv[7], wv[0], wv[1]) + sha256_k[5] + w[5];
		t2 = SHA256_F1(wv[3]) + MAJ(wv[3], wv[4], wv[5]);
		wv[6] = wv[6] + t1;
		wv[2] = t1 + t2;

		t1 = wv[1] + SHA256_F2(wv[6]) + CH(wv[6], wv[7], wv[0]) + sha256_k[6] + w[6];
		t2 = SHA256_F1(wv[2]) + MAJ(wv[2], wv[3], wv[4]);
		wv[5] = wv[5] + t1;
		wv[1] = t1 + t2;

		t1 = wv[0] + SHA256_F2(wv[5]) + CH(wv[5], wv[6], wv[7]) + sha256_k[7] + w[7];
		t2 = SHA256_F1(wv[1]) + MAJ(wv[1], wv[2], wv[3]);
		wv[4] = wv[4] + t1;
		wv[0] = t1 + t2;

		t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4], wv[5], wv[6]) + sha256_k[8] + w[8];
		t2 = SHA256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
		wv[3] = wv[3] + t1;
		wv[7] = t1 + t2;

		t1 = wv[6] + SHA256_F2(wv[3]) + CH(wv[3], wv[4], wv[5]) + sha256_k[9] + w[9];
		t2 = SHA256_F1(wv[7]) + MAJ(wv[7], wv[0], wv[1]);
		wv[2] = wv[2] + t1;
		wv[6] = t1 + t2;

		t1 = wv[5] + SHA256_F2(wv[2]) + CH(wv[2], wv[3], wv[4]) + sha256_k[10] + w[10];
		t2 = SHA256_F1(wv[6]) + MAJ(wv[6], wv[7], wv[0]);
		wv[1] = wv[1] + t1;
		wv[5] = t1 + t2;

		t1 = wv[4] + SHA256_F2(wv[1]) + CH(wv[1], wv[2], wv[3]) + sha256_k[11] + w[11];
		t2 = SHA256_F1(wv[5]) + MAJ(wv[5], wv[6], wv[7]);
		wv[0] = wv[0] + t1;
		wv[4] = t1 + t2;

		t1 = wv[3] + SHA256_F2(wv[0]) + CH(wv[0], wv[1], wv[2]) + sha256_k[12] + w[12];
		t2 = SHA256_F1(wv[4]) + MAJ(wv[4], wv[5], wv[6]);
		wv[7] = wv[7] + t1;
		wv[3] = t1 + t2;

		t1 = wv[2] + SHA256_F2(wv[7]) + CH(wv[7], wv[0], wv[1]) + sha256_k[13] + w[13];
		t2 = SHA256_F1(wv[3]) + MAJ(wv[3], wv[4], wv[5]);
		wv[6] = wv[6] + t1;
		wv[2] = t1 + t2;

		t1 = wv[1] + SHA256_F2(wv[6]) + CH(wv[6], wv[7], wv[0]) + sha256_k[14] + w[14];
		t2 = SHA256_F1(wv[2]) + MAJ(wv[2], wv[3], wv[4]);
		wv[5] = wv[5] + t1;
		wv[1] = t1 + t2;

		t1 = wv[0] + SHA256_F2(wv[5]) + CH(wv[5], wv[6], wv[7]) + sha256_k[15] + w[15];
		t2 = SHA256_F1(wv[1]) + MAJ(wv[1], wv[2], wv[3]);
		wv[4] = wv[4] + t1;
		wv[0] = t1 + t2;

		t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4], wv[5], wv[6]) + sha256_k[16] + w[16];
		t2 = SHA256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
		wv[3] = wv[3] + t1;
		wv[7] = t1 + t2;

		t1 = wv[6] + SHA256_F2(wv[3]) + CH(wv[3], wv[4], wv[5]) + sha256_k[17] + w[17];
		t2 = SHA256_F1(wv[7]) + MAJ(wv[7], wv[0], wv[1]);
		wv[2] = wv[2] + t1;
		wv[6] = t1 + t2;

		t1 = wv[5] + SHA256_F2(wv[2]) + CH(wv[2], wv[3], wv[4]) + sha256_k[18] + w[18];
		t2 = SHA256_F1(wv[6]) + MAJ(wv[6], wv[7], wv[0]);
		wv[1] = wv[1] + t1;
		wv[5] = t1 + t2;

		t1 = wv[4] + SHA256_F2(wv[1]) + CH(wv[1], wv[2], wv[3]) + sha256_k[19] + w[19];
		t2 = SHA256_F1(wv[5]) + MAJ(wv[5], wv[6], wv[7]);
		wv[0] = wv[0] + t1;
		wv[4] = t1 + t2;

		t1 = wv[3] + SHA256_F2(wv[0]) + CH(wv[0], wv[1], wv[2]) + sha256_k[20] + w[20];
		t2 = SHA256_F1(wv[4]) + MAJ(wv[4], wv[5], wv[6]);
		wv[7] = wv[7] + t1;
		wv[3] = t1 + t2;

		t1 = wv[2] + SHA256_F2(wv[7]) + CH(wv[7], wv[0], wv[1]) + sha256_k[21] + w[21];
		t2 = SHA256_F1(wv[3]) + MAJ(wv[3], wv[4], wv[5]);
		wv[6] = wv[6] + t1;
		wv[2] = t1 + t2;

		t1 = wv[1] + SHA256_F2(wv[6]) + CH(wv[6], wv[7], wv[0]) + sha256_k[22] + w[22];
		t2 = SHA256_F1(wv[2]) + MAJ(wv[2], wv[3], wv[4]);
		wv[5] = wv[5] + t1;
		wv[1] = t1 + t2;

		t1 = wv[0] + SHA256_F2(wv[5]) + CH(wv[5], wv[6], wv[7]) + sha256_k[23] + w[23];
		t2 = SHA256_F1(wv[1]) + MAJ(wv[1], wv[2], wv[3]);
		wv[4] = wv[4] + t1;
		wv[0] = t1 + t2;

		t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4], wv[5], wv[6]) + sha256_k[24] + w[24];
		t2 = SHA256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
		wv[3] = wv[3] + t1;
		wv[7] = t1 + t2;

		t1 = wv[6] + SHA256_F2(wv[3]) + CH(wv[3], wv[4], wv[5]) + sha256_k[25] + w[25];
		t2 = SHA256_F1(wv[7]) + MAJ(wv[7], wv[0], wv[1]);
		wv[2] = wv[2] + t1;
		wv[6] = t1 + t2;

		t1 = wv[5] + SHA256_F2(wv[2]) + CH(wv[2], wv[3], wv[4]) + sha256_k[26] + w[26];
		t2 = SHA256_F1(wv[6]) + MAJ(wv[6], wv[7], wv[0]);
		wv[1] = wv[1] + t1;
		wv[5] = t1 + t2;

		t1 = wv[4] + SHA256_F2(wv[1]) + CH(wv[1], wv[2], wv[3]) + sha256_k[27] + w[27];
		t2 = SHA256_F1(wv[5]) + MAJ(wv[5], wv[6], wv[7]);
		wv[0] = wv[0] + t1;
		wv[4] = t1 + t2;

		t1 = wv[3] + SHA256_F2(wv[0]) + CH(wv[0], wv[1], wv[2]) + sha256_k[28] + w[28];
		t2 = SHA256_F1(wv[4]) + MAJ(wv[4], wv[5], wv[6]);
		wv[7] = wv[7] + t1;
		wv[3] = t1 + t2;

		t1 = wv[2] + SHA256_F2(wv[7]) + CH(wv[7], wv[0], wv[1]) + sha256_k[29] + w[29];
		t2 = SHA256_F1(wv[3]) + MAJ(wv[3], wv[4], wv[5]);
		wv[6] = wv[6] + t1;
		wv[2] = t1 + t2;

		t1 = wv[1] + SHA256_F2(wv[6]) + CH(wv[6], wv[7], wv[0]) + sha256_k[30] + w[30];
		t2 = SHA256_F1(wv[2]) + MAJ(wv[2], wv[3], wv[4]);
		wv[5] = wv[5] + t1;
		wv[1] = t1 + t2;

		t1 = wv[0] + SHA256_F2(wv[5]) + CH(wv[5], wv[6], wv[7]) + sha256_k[31] + w[31];
		t2 = SHA256_F1(wv[1]) + MAJ(wv[1], wv[2], wv[3]);
		wv[4] = wv[4] + t1;
		wv[0] = t1 + t2;

		t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4], wv[5], wv[6]) + sha256_k[32] + w[32];
		t2 = SHA256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
		wv[3] = wv[3] + t1;
		wv[7] = t1 + t2;

		t1 = wv[6] + SHA256_F2(wv[3]) + CH(wv[3], wv[4], wv[5]) + sha256_k[33] + w[33];
		t2 = SHA256_F1(wv[7]) + MAJ(wv[7], wv[0], wv[1]);
		wv[2] = wv[2] + t1;
		wv[6] = t1 + t2;

		t1 = wv[5] + SHA256_F2(wv[2]) + CH(wv[2], wv[3], wv[4]) + sha256_k[34] + w[34];
		t2 = SHA256_F1(wv[6]) + MAJ(wv[6], wv[7], wv[0]);
		wv[1] = wv[1] + t1;
		wv[5] = t1 + t2;

		t1 = wv[4] + SHA256_F2(wv[1]) + CH(wv[1], wv[2], wv[3]) + sha256_k[35] + w[35];
		t2 = SHA256_F1(wv[5]) + MAJ(wv[5], wv[6], wv[7]);
		wv[0] = wv[0] + t1;
		wv[4] = t1 + t2;

		t1 = wv[3] + SHA256_F2(wv[0]) + CH(wv[0], wv[1], wv[2]) + sha256_k[36] + w[36];
		t2 = SHA256_F1(wv[4]) + MAJ(wv[4], wv[5], wv[6]);
		wv[7] = wv[7] + t1;
		wv[3] = t1 + t2;

		t1 = wv[2] + SHA256_F2(wv[7]) + CH(wv[7], wv[0], wv[1]) + sha256_k[37] + w[37];
		t2 = SHA256_F1(wv[3]) + MAJ(wv[3], wv[4], wv[5]);
		wv[6] = wv[6] + t1;
		wv[2] = t1 + t2;

		t1 = wv[1] + SHA256_F2(wv[6]) + CH(wv[6], wv[7], wv[0]) + sha256_k[38] + w[38];
		t2 = SHA256_F1(wv[2]) + MAJ(wv[2], wv[3], wv[4]);
		wv[5] = wv[5] + t1;
		wv[1] = t1 + t2;

		t1 = wv[0] + SHA256_F2(wv[5]) + CH(wv[5], wv[6], wv[7]) + sha256_k[39] + w[39];
		t2 = SHA256_F1(wv[1]) + MAJ(wv[1], wv[2], wv[3]);
		wv[4] = wv[4] + t1;
		wv[0] = t1 + t2;

		t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4], wv[5], wv[6]) + sha256_k[40] + w[40];
		t2 = SHA256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
		wv[3] = wv[3] + t1;
		wv[7] = t1 + t2;

		t1 = wv[6] + SHA256_F2(wv[3]) + CH(wv[3], wv[4], wv[5]) + sha256_k[41] + w[41];
		t2 = SHA256_F1(wv[7]) + MAJ(wv[7], wv[0], wv[1]);
		wv[2] = wv[2] + t1;
		wv[6] = t1 + t2;

		t1 = wv[5] + SHA256_F2(wv[2]) + CH(wv[2], wv[3], wv[4]) + sha256_k[42] + w[42];
		t2 = SHA256_F1(wv[6]) + MAJ(wv[6], wv[7], wv[0]);
		wv[1] = wv[1] + t1;
		wv[5] = t1 + t2;

		t1 = wv[4] + SHA256_F2(wv[1]) + CH(wv[1], wv[2], wv[3]) + sha256_k[43] + w[43];
		t2 = SHA256_F1(wv[5]) + MAJ(wv[5], wv[6], wv[7]);
		wv[0] = wv[0] + t1;
		wv[4] = t1 + t2;

		t1 = wv[3] + SHA256_F2(wv[0]) + CH(wv[0], wv[1], wv[2]) + sha256_k[44] + w[44];
		t2 = SHA256_F1(wv[4]) + MAJ(wv[4], wv[5], wv[6]);
		wv[7] = wv[7] + t1;
		wv[3] = t1 + t2;

		t1 = wv[2] + SHA256_F2(wv[7]) + CH(wv[7], wv[0], wv[1]) + sha256_k[45] + w[45];
		t2 = SHA256_F1(wv[3]) + MAJ(wv[3], wv[4], wv[5]);
		wv[6] = wv[6] + t1;
		wv[2] = t1 + t2;

		t1 = wv[1] + SHA256_F2(wv[6]) + CH(wv[6], wv[7], wv[0]) + sha256_k[46] + w[46];
		t2 = SHA256_F1(wv[2]) + MAJ(wv[2], wv[3], wv[4]);
		wv[5] = wv[5] + t1;
		wv[1] = t1 + t2;

		t1 = wv[0] + SHA256_F2(wv[5]) + CH(wv[5], wv[6], wv[7]) + sha256_k[47] + w[47];
		t2 = SHA256_F1(wv[1]) + MAJ(wv[1], wv[2], wv[3]);
		wv[4] = wv[4] + t1;
		wv[0] = t1 + t2;

		t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4], wv[5], wv[6]) + sha256_k[48] + w[48];
		t2 = SHA256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
		wv[3] = wv[3] + t1;
		wv[7] = t1 + t2;

		t1 = wv[6] + SHA256_F2(wv[3]) + CH(wv[3], wv[4], wv[5]) + sha256_k[49] + w[49];
		t2 = SHA256_F1(wv[7]) + MAJ(wv[7], wv[0], wv[1]);
		wv[2] = wv[2] + t1;
		wv[6] = t1 + t2;

		t1 = wv[5] + SHA256_F2(wv[2]) + CH(wv[2], wv[3], wv[4]) + sha256_k[50] + w[50];
		t2 = SHA256_F1(wv[6]) + MAJ(wv[6], wv[7], wv[0]);
		wv[1] = wv[1] + t1;
		wv[5] = t1 + t2;

		t1 = wv[4] + SHA256_F2(wv[1]) + CH(wv[1], wv[2], wv[3]) + sha256_k[51] + w[51];
		t2 = SHA256_F1(wv[5]) + MAJ(wv[5], wv[6], wv[7]);
		wv[0] = wv[0] + t1;
		wv[4] = t1 + t2;

		t1 = wv[3] + SHA256_F2(wv[0]) + CH(wv[0], wv[1], wv[2]) + sha256_k[52] + w[52];
		t2 = SHA256_F1(wv[4]) + MAJ(wv[4], wv[5], wv[6]);
		wv[7] = wv[7] + t1;
		wv[3] = t1 + t2;

		t1 = wv[2] + SHA256_F2(wv[7]) + CH(wv[7], wv[0], wv[1]) + sha256_k[53] + w[53];
		t2 = SHA256_F1(wv[3]) + MAJ(wv[3], wv[4], wv[5]);
		wv[6] = wv[6] + t1;
		wv[2] = t1 + t2;

		t1 = wv[1] + SHA256_F2(wv[6]) + CH(wv[6], wv[7], wv[0]) + sha256_k[54] + w[54];
		t2 = SHA256_F1(wv[2]) + MAJ(wv[2], wv[3], wv[4]);
		wv[5] = wv[5] + t1;
		wv[1] = t1 + t2;

		t1 = wv[0] + SHA256_F2(wv[5]) + CH(wv[5], wv[6], wv[7]) + sha256_k[55] + w[55];
		t2 = SHA256_F1(wv[1]) + MAJ(wv[1], wv[2], wv[3]);
		wv[4] = wv[4] + t1;
		wv[0] = t1 + t2;

		t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4], wv[5], wv[6]) + sha256_k[56] + w[56];
		t2 = SHA256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
		wv[3] = wv[3] + t1;
		wv[7] = t1 + t2;

		t1 = wv[6] + SHA256_F2(wv[3]) + CH(wv[3], wv[4], wv[5]) + sha256_k[57] + w[57];
		t2 = SHA256_F1(wv[7]) + MAJ(wv[7], wv[0], wv[1]);
		wv[2] = wv[2] + t1;
		wv[6] = t1 + t2;

		t1 = wv[5] + SHA256_F2(wv[2]) + CH(wv[2], wv[3], wv[4]) + sha256_k[58] + w[58];
		t2 = SHA256_F1(wv[6]) + MAJ(wv[6], wv[7], wv[0]);
		wv[1] = wv[1] + t1;
		wv[5] = t1 + t2;

		t1 = wv[4] + SHA256_F2(wv[1]) + CH(wv[1], wv[2], wv[3]) + sha256_k[59] + w[59];
		t2 = SHA256_F1(wv[5]) + MAJ(wv[5], wv[6], wv[7]);
		wv[0] = wv[0] + t1;
		wv[4] = t1 + t2;

		t1 = wv[3] + SHA256_F2(wv[0]) + CH(wv[0], wv[1], wv[2]) + sha256_k[60] + w[60];
		t2 = SHA256_F1(wv[4]) + MAJ(wv[4], wv[5], wv[6]);
		wv[7] = wv[7] + t1;
		wv[3] = t1 + t2;

		t1 = wv[2] + SHA256_F2(wv[7]) + CH(wv[7], wv[0], wv[1]) + sha256_k[61] + w[61];
		t2 = SHA256_F1(wv[3]) + MAJ(wv[3], wv[4], wv[5]);
		wv[6] = wv[6] + t1;
		wv[2] = t1 + t2;

		t1 = wv[1] + SHA256_F2(wv[6]) + CH(wv[6], wv[7], wv[0]) + sha256_k[62] + w[62];
		t2 = SHA256_F1(wv[2]) + MAJ(wv[2], wv[3], wv[4]);
		wv[5] = wv[5] + t1;
		wv[1] = t1 + t2;

		t1 = wv[0] + SHA256_F2(wv[5]) + CH(wv[5], wv[6], wv[7]) + sha256_k[63] + w[63];
		t2 = SHA256_F1(wv[1]) + MAJ(wv[1], wv[2], wv[3]);
		wv[4] = wv[4] + t1;
		wv[0] = t1 + t2;

        for (j = 0; j < 8; j++) {
            ctx->h[j] += wv[j];
        }
    }
}

void sha256(const unsigned char *message, unsigned int len, unsigned char *digest)
{
    sha256_ctx ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, message, len);
    sha256_final(&ctx, digest);
}

void sha256_init(sha256_ctx *ctx)
{
    int i;
    for (i = 0; i < 8; i++) {
        ctx->h[i] = sha256_h0[i];
    }

    ctx->len = 0;
    ctx->tot_len = 0;
}

void sha256_update(sha256_ctx *ctx, const unsigned char *message,
                   unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;

    tmp_len = SHA256_BLOCK_SIZE - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&ctx->block[ctx->len], message, rem_len);

    if (ctx->len + len < SHA256_BLOCK_SIZE) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA256_BLOCK_SIZE;

    shifted_message = message + rem_len;

    sha256_transf(ctx, ctx->block, 1);
    sha256_transf(ctx, shifted_message, block_nb);

    rem_len = new_len % SHA256_BLOCK_SIZE;

    memcpy(ctx->block, &shifted_message[block_nb << 6],
           rem_len);

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 6;
}

void sha256_final(sha256_ctx *ctx, unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;

    int i;

    block_nb = (1 + ((SHA256_BLOCK_SIZE - 9)
                     < (ctx->len % SHA256_BLOCK_SIZE)));

    len_b = (ctx->tot_len + ctx->len) << 3;
    pm_len = block_nb << 6;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;
    UNPACK32(len_b, ctx->block + pm_len - 4);

    sha256_transf(ctx, ctx->block, block_nb);

    for (i = 0 ; i < 8; i++) {
        UNPACK32(ctx->h[i], &digest[i << 2]);
    }
}
