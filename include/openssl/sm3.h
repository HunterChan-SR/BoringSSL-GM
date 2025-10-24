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

#ifndef OPENSSL_HEADER_SM3_H
#define OPENSSL_HEADER_SM3_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


// SM3.


// SM3_CBLOCK is the block size of SM3.
#define SM3_CBLOCK 64

// SM3_DIGEST_LENGTH is the length of an SM3 digest.
#define SM3_DIGEST_LENGTH 32

// SM3_Init initialises |sm3| and returns one.
OPENSSL_EXPORT int SM3_Init(SM3_CTX *sm3);

// SM3_Update adds |len| bytes from |data| to |sm3| and returns one.
OPENSSL_EXPORT int SM3_Update(SM3_CTX *sm3, const void *data, size_t len);

// SM3_Final adds the final padding to |sm3| and writes the resulting digest to
// |out|, which must have at least |SM3_DIGEST_LENGTH| bytes of space. It
// returns one.
OPENSSL_EXPORT int SM3_Final(uint8_t out[SM3_DIGEST_LENGTH], SM3_CTX *sm3);

// SM3 writes the digest of |len| bytes from |data| to |out| and returns |out|.
// There must be at least |SM3_DIGEST_LENGTH| bytes of space in |out|.
OPENSSL_EXPORT uint8_t *SM3(const uint8_t *data, size_t len,
                           uint8_t out[SM3_DIGEST_LENGTH]);

// SM3_Transform is a low-level function that performs a single, SM3 block
// transformation using the state from |sm3| and 64 bytes from |block|.
OPENSSL_EXPORT void SM3_Transform(SM3_CTX *sm3,
                                const uint8_t block[SM3_CBLOCK]);

struct sm3_state_st {
  uint32_t h[8];  // SM3 uses 8 32-bit words for state, unlike MD5's 4
  uint32_t Nl, Nh;
  uint8_t data[SM3_CBLOCK];
  unsigned num;
};


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_SM3_H