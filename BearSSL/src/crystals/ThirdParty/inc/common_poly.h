#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "inner.h"

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct{
  int16_t coeffs[256];
} poly;

void poly_compress(uint8_t *r, size_t rlen, poly *a);
void poly_decompress(poly *r, const uint8_t *a, size_t alen);

void poly_tobytes(uint8_t *r, size_t rlen, poly *a);
void poly_frombytes(poly *r, const uint8_t *a, size_t alen);

void poly_frommsg(poly *r, const uint8_t *msg, size_t msglen);
void poly_tomsg(uint8_t *msg, size_t msglen, poly *r);

void poly_getnoise(poly *r, const uint8_t *seed, size_t seedlen,  uint8_t nonce);

void poly_ntt(poly *r);
void poly_invntt_tomont(poly *r);
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
void poly_tomont(poly *r);

void poly_reduce(poly *r);
void poly_csubq(poly *r);

void poly_add(poly *r, const poly *a, const poly *b);
void poly_sub(poly *r, const poly *a, const poly *b);

#endif
