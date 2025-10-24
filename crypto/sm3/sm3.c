/* Copyright (C) 2023 The 陈贺(HeChen) Authors
 * All rights reserved.
 *
 * This package implements the SM3 hash function as specified in 
 * GM/T 0004-2012: SM3 Cryptographic Hash Algorithm.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. */
#include <string.h>
#include <stdint.h>
#include <openssl/sm3.h>

#define ROTL(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

static inline uint32_t GETU32(const uint8_t *b) {
  return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
         ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static inline void PUTU32(uint8_t *b, uint32_t v) {
  b[0] = (uint8_t)(v >> 24);
  b[1] = (uint8_t)(v >> 16);
  b[2] = (uint8_t)(v >> 8);
  b[3] = (uint8_t)v;
}

/* SM3 permutation helpers */
#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))
#define FF(j, x, y, z) ((j) < 16 ? ((x) ^ (y) ^ (z)) : (((x) & (y)) | ((x) & (z)) | ((y) & (z))))
#define GG(j, x, y, z) ((j) < 16 ? ((x) ^ (y) ^ (z)) : (((x) & (y)) | ((~(x)) & (z))))

static const uint32_t Tj[64] = {
	0x79cc4519U, 0xf3988a32U, 0xe7311465U, 0xce6228cbU,
	0x9cc45197U, 0x3988a32fU, 0x7311465eU, 0xe6228cbcU,
	0xcc451979U, 0x988a32f3U, 0x311465e7U, 0x6228cbceU,
	0xc451979cU, 0x88a32f39U, 0x11465e73U, 0x228cbce6U,
	0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
	0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
	0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
	0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
	0x7a879d8aU, 0xf50f3b14U, 0xea1e7629U, 0xd43cec53U,
	0xa879d8a7U, 0x50f3b14fU, 0xa1e7629eU, 0x43cec53dU,
	0x879d8a7aU, 0x0f3b14f5U, 0x1e7629eaU, 0x3cec53d4U,
	0x79d8a7a8U, 0xf3b14f50U, 0xe7629ea1U, 0xcec53d43U,
	0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
	0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
	0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
	0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
};

OPENSSL_EXPORT int SM3_Init(SM3_CTX *sm3) {
  if (sm3 == NULL) return 0;
  /* IV as per SM3 standard */
  sm3->h[0] = 0x7380166fU;
  sm3->h[1] = 0x4914b2b9U;
  sm3->h[2] = 0x172442d7U;
  sm3->h[3] = 0xda8a0600U;
  sm3->h[4] = 0xa96f30bcU;
  sm3->h[5] = 0x163138aaU;
  sm3->h[6] = 0xe38dee4dU;
  sm3->h[7] = 0xb0fb0e4eU;
  sm3->Nl = sm3->Nh = 0;
  sm3->num = 0;
  return 1;
}

OPENSSL_EXPORT void SM3_Transform(SM3_CTX *sm3, const uint8_t block[SM3_CBLOCK]) {
  uint32_t W[68], W1[64];
  uint32_t A, B, C, D, E, F, G, H;
  uint32_t SS1, SS2, TT1, TT2;
  int j;

  for (j = 0; j < 16; j++) {
    W[j] = GETU32(block + j * 4);
  }
  for (j = 16; j < 68; j++) {
    W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
  }
  for (j = 0; j < 64; j++) {
    W1[j] = W[j] ^ W[j + 4];
  }

  A = sm3->h[0];
  B = sm3->h[1];
  C = sm3->h[2];
  D = sm3->h[3];
  E = sm3->h[4];
  F = sm3->h[5];
  G = sm3->h[6];
  H = sm3->h[7];

  for (j = 0; j < 64; j++) {
    uint32_t T = Tj[j];
    SS1 = ROTL((ROTL(A, 12) + E + ROTL(T, j)) , 7);
    SS2 = SS1 ^ ROTL(A, 12);
    TT1 = FF(j, A, B, C) + D + SS2 + W1[j];
    TT2 = GG(j, E, F, G) + H + SS1 + W[j];
    D = C;
    C = ROTL(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = ROTL(F, 19);
    F = E;
    E = P0(TT2);
  }

  sm3->h[0] ^= A;
  sm3->h[1] ^= B;
  sm3->h[2] ^= C;
  sm3->h[3] ^= D;
  sm3->h[4] ^= E;
  sm3->h[5] ^= F;
  sm3->h[6] ^= G;
  sm3->h[7] ^= H;
}

OPENSSL_EXPORT int SM3_Update(SM3_CTX *sm3, const void *data, size_t len) {
  const uint8_t *inp = (const uint8_t *)data;
  size_t fill, left;

  if (len == 0) return 1;
  left = sm3->num;
  fill = SM3_CBLOCK - left;

  /* update bit count */
  uint32_t bits = (uint32_t)(len << 3);
  uint32_t prev = sm3->Nl;
  sm3->Nl += bits;
  if (sm3->Nl < prev) /* overflow */
    sm3->Nh++;

  /* also add carry from len (bytes) overflowing 32-bit when multiplied by 8 */
  /* (handled by above because bits is modulo 2^32) */

  if (left && len >= fill) {
    memcpy(sm3->data + left, inp, fill);
    SM3_Transform(sm3, sm3->data);
    inp += fill;
    len -= fill;
    left = 0;
  }

  while (len >= SM3_CBLOCK) {
    SM3_Transform(sm3, inp);
    inp += SM3_CBLOCK;
    len -= SM3_CBLOCK;
  }

  if (len) {
    memcpy(sm3->data + left, inp, len);
    sm3->num = left + (unsigned)len;
  } else {
    sm3->num = 0;
  }

  return 1;
}

OPENSSL_EXPORT int SM3_Final(uint8_t out[SM3_DIGEST_LENGTH], SM3_CTX *sm3) {
  uint8_t msglen[8];
  unsigned int i;
  uint32_t left = sm3->num;

  /* total bits in big-endian 64-bit */
  uint32_t high = sm3->Nh;
  uint32_t low = sm3->Nl;
  PUTU32(msglen, high);
  PUTU32(msglen + 4, low);

  /* append 0x80 */
  uint8_t padding[SM3_CBLOCK * 2];
  memset(padding, 0, sizeof(padding));
  padding[0] = 0x80;

  /* pad: enough to leave 8 bytes for length */
  unsigned int padlen = (left < 56) ? (56 - left) : (120 - left);
  SM3_Update(sm3, padding, padlen);
  SM3_Update(sm3, msglen, 8);

  /* output digest in big-endian */
  for (i = 0; i < 8; i++) {
    PUTU32(out + i * 4, sm3->h[i]);
  }

  /* clear sensitive data */
  memset(sm3, 0, sizeof(*sm3));
  return 1;
}

OPENSSL_EXPORT uint8_t *SM3(const uint8_t *data, size_t len, uint8_t out[SM3_DIGEST_LENGTH]) {
  static uint8_t local_out[SM3_DIGEST_LENGTH];
  SM3_CTX ctx;
  SM3_Init(&ctx);
  if (len) SM3_Update(&ctx, data, len);
  SM3_Final(out ? out : local_out, &ctx);
  return out ? out : local_out;
}
