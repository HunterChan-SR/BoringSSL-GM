/* Copyright (c) 2023, SM2 Developers 陈贺 */
/* See LICENSE for licensing information */


/* sm2.h
 *
 * SM2 curve header (参考 p256-nistz.h 风格)
 *
 * Curve: SM2 (SM2P256v1) - GM/T 0003.5 / GM/T 0003.1-2012
 *
 * Copyright: (use as you need)
 *
 * 说明:
 *  - 该头文件只定义接口和类型，不包含具体实现。
 *  - 常量以 extern 形式声明；可在实现文件中按目标平台的 BN_ULONG 布局定义。
 */

#ifndef OPENSSL_HEADER_EC_SM2_H
#define OPENSSL_HEADER_EC_SM2_H

#include <openssl/base.h>
#include <openssl/bn.h>
#include "../bn/internal.h"

#if defined(__cplusplus)
extern "C" {
#endif


#if !defined(OPENSSL_NO_ASM) && \
    (defined(OPENSSL_X86_64) || defined(OPENSSL_AARCH64)) &&   \
    !defined(OPENSSL_SMALL)

// SM2 field operations (mod p)
//
// SM2 is based on prime field GF(p), where p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
// An element mod p is represented as a little-endian array of |SM2_LIMBS| |BN_ULONG|s.
// Inputs are fully-reduced mod p, outputs are also fully-reduced mod p. All functions support in-place operation.

#define SM2_LIMBS (256 / BN_BITS2)  // 256-bit field, number of limbs depends on BN_ULONG width

// ecp_sm2_neg sets |res| to -|a| mod p.
void ecp_sm2_neg(BN_ULONG res[SM2_LIMBS], const BN_ULONG a[SM2_LIMBS]);

// ecp_sm2_mont_mul sets |res| to |a| * |b| * 2^-256 mod p (Montgomery multiplication).
#if defined(OPENSSL_X86_64)
void ecp_sm2_mont_mul_nohw(BN_ULONG res[SM2_LIMBS],
                           const BN_ULONG a[SM2_LIMBS],
                           const BN_ULONG b[SM2_LIMBS]);
void ecp_sm2_mont_mul_adx(BN_ULONG res[SM2_LIMBS],
                          const BN_ULONG a[SM2_LIMBS],
                          const BN_ULONG b[SM2_LIMBS]);
#else
void ecp_sm2_mont_mul(BN_ULONG res[SM2_LIMBS],
                      const BN_ULONG a[SM2_LIMBS],
                      const BN_ULONG b[SM2_LIMBS]);
#endif

// ecp_sm2_mont_sqr sets |res| to |a|^2 * 2^-256 mod p (Montgomery squaring).
#if defined(OPENSSL_X86_64)
void ecp_sm2_mont_sqr_nohw(BN_ULONG res[SM2_LIMBS],
                           const BN_ULONG a[SM2_LIMBS]);
void ecp_sm2_mont_sqr_adx(BN_ULONG res[SM2_LIMBS],
                          const BN_ULONG a[SM2_LIMBS]);
#else
void ecp_sm2_mont_sqr(BN_ULONG res[SM2_LIMBS],
                      const BN_ULONG a[SM2_LIMBS]);
#endif


// SM2 scalar operations (mod N)
//
// N is the order of SM2 elliptic curve: N = 2^256 - 2^224 + 2^192 - 2^64 - 1.
// Inputs are fully-reduced mod N, outputs are also fully-reduced mod N.

// ecp_sm2_ord_mont_mul sets |res| to |a| * |b| * 2^-256 mod N (Montgomery scalar multiplication).
// Inputs and outputs are in Montgomery form.
#if defined(OPENSSL_X86_64)
void ecp_sm2_ord_mont_mul_nohw(BN_ULONG res[SM2_LIMBS],
                               const BN_ULONG a[SM2_LIMBS],
                               const BN_ULONG b[SM2_LIMBS]);
void ecp_sm2_ord_mont_mul_adx(BN_ULONG res[SM2_LIMBS],
                              const BN_ULONG a[SM2_LIMBS],
                              const BN_ULONG b[SM2_LIMBS]);
#else
void ecp_sm2_ord_mont_mul(BN_ULONG res[SM2_LIMBS],
                          const BN_ULONG a[SM2_LIMBS],
                          const BN_ULONG b[SM2_LIMBS]);
#endif

// ecp_sm2_ord_mont_sqr sets |res| to (|a| * 2^-256)^(2*|rep|) * 2^256 mod N (Montgomery scalar squaring).
// Inputs and outputs are in Montgomery form; |rep| is the number of squaring iterations.
#if defined(OPENSSL_X86_64)
void ecp_sm2_ord_mont_sqr_nohw(BN_ULONG res[SM2_LIMBS],
                               const BN_ULONG a[SM2_LIMBS], BN_ULONG rep);
void ecp_sm2_ord_mont_sqr_adx(BN_ULONG res[SM2_LIMBS],
                              const BN_ULONG a[SM2_LIMBS], BN_ULONG rep);
#else
void ecp_sm2_ord_mont_sqr(BN_ULONG res[SM2_LIMBS],
                          const BN_ULONG a[SM2_LIMBS], BN_ULONG rep);
#endif

// ecp_sm2_mod_inverse_vartime computes |out| = |a|^-1 mod p using extended Euclidean algorithm.
// Assumption: 0 < a < p, and p is the SM2 prime field modulus.
int ecp_sm2_mod_inverse_vartime(BN_ULONG out[SM2_LIMBS],
                                const BN_ULONG a[SM2_LIMBS],
                                const BN_ULONG p[SM2_LIMBS]);


// SM2 point operations
//
// All point coordinates are in Montgomery domain. Functions support in-place operation.

// SM2_POINT represents an SM2 elliptic curve point in Jacobian coordinates (X:Y:Z).
typedef struct {
    BN_ULONG X[SM2_LIMBS];  // X coordinate
    BN_ULONG Y[SM2_LIMBS];  // Y coordinate
    BN_ULONG Z[SM2_LIMBS];  // Z coordinate (Jacobian parameter)
} SM2_POINT;

// SM2_POINT_AFFINE represents an SM2 elliptic curve point in affine coordinates (X,Y).
// The point at infinity is encoded as (0, 0).
typedef struct {
    BN_ULONG X[SM2_LIMBS];  // X coordinate
    BN_ULONG Y[SM2_LIMBS];  // Y coordinate
} SM2_POINT_AFFINE;

// ecp_sm2_select_w5 selects a point from |in_t| (16 points) based on |index|, in constant time.
// - 1 ≤ |index| ≤ 16: |val| = |in_t[index-1]|
// - |index| = 0: |val| = point at infinity (all zeros)
#if defined(OPENSSL_X86_64)
void ecp_sm2_select_w5_nohw(SM2_POINT *val, const SM2_POINT in_t[16], int index);
void ecp_sm2_select_w5_avx2(SM2_POINT *val, const SM2_POINT in_t[16], int index);
#else
void ecp_sm2_select_w5(SM2_POINT *val, const SM2_POINT in_t[16], int index);
#endif

// ecp_sm2_select_w7 selects a point from |in_t| (64 points) based on |index|, in constant time.
// - 1 ≤ |index| ≤ 64: |val| = |in_t[index-1]|
// - |index| = 0: |val| = point at infinity (all zeros)
#if defined(OPENSSL_X86_64)
void ecp_sm2_select_w7_nohw(SM2_POINT_AFFINE *val, const SM2_POINT_AFFINE in_t[64], int index);
void ecp_sm2_select_w7_avx2(SM2_POINT_AFFINE *val, const SM2_POINT_AFFINE in_t[64], int index);
#else
void ecp_sm2_select_w7(SM2_POINT_AFFINE *val, const SM2_POINT_AFFINE in_t[64], int index);
#endif

// ecp_sm2_point_double sets |r| to the double of |a| (r = 2*a).
#if defined(OPENSSL_X86_64)
void ecp_sm2_point_double_nohw(SM2_POINT *r, const SM2_POINT *a);
void ecp_sm2_point_double_adx(SM2_POINT *r, const SM2_POINT *a);
#else
void ecp_sm2_point_double(SM2_POINT *r, const SM2_POINT *a);
#endif

// ecp_sm2_point_add sets |r| to the sum of |a| and |b| (r = a + b).
#if defined(OPENSSL_X86_64)
void ecp_sm2_point_add_nohw(SM2_POINT *r, const SM2_POINT *a, const SM2_POINT *b);
void ecp_sm2_point_add_adx(SM2_POINT *r, const SM2_POINT *a, const SM2_POINT *b);
#else
void ecp_sm2_point_add(SM2_POINT *r, const SM2_POINT *a, const SM2_POINT *b);
#endif

// ecp_sm2_point_add_affine sets |r| to the sum of |a| (Jacobian) and |b| (affine).
// Constraint: |a| and |b| must not be the same point (unless both are infinity).
#if defined(OPENSSL_X86_64)
void ecp_sm2_point_add_affine_nohw(SM2_POINT *r, const SM2_POINT *a, const SM2_POINT_AFFINE *b);
void ecp_sm2_point_add_affine_adx(SM2_POINT *r, const SM2_POINT *a, const SM2_POINT_AFFINE *b);
#else
void ecp_sm2_point_add_affine(SM2_POINT *r, const SM2_POINT *a, const SM2_POINT_AFFINE *b);
#endif

#endif /* !defined(OPENSSL_NO_ASM) && (X86_64/AARCH64) && !OPENSSL_SMALL */


#if defined(__cplusplus)
}  // extern "C"
#endif

#endif  // OPENSSL_HEADER_EC_SM2_H