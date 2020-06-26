#ifndef KYBER_POLY_H
#define KYBER_POLY_H

#include <stdint.h>
#include <stddef.h>

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct {
    int16_t coeffs[256];
} br_kyber_third_party_poly;

void br_kyber_third_party_poly_compress(uint8_t *r, unsigned polynbr, br_kyber_third_party_poly *a);

void br_kyber_third_party_poly_decompress(br_kyber_third_party_poly *r, const uint8_t *a, unsigned polynbr);

// This function assumes a large enough buffer is passed
void br_kyber_third_party_poly_tobytes(uint8_t *r, br_kyber_third_party_poly *a);

// This function assumes a large enough buffer is passed
void br_kyber_third_party_poly_frombytes(br_kyber_third_party_poly *r, const uint8_t *a);

// This function assumes a large enough buffer is passed
void br_kyber_third_party_poly_tomsg(uint8_t *msg, br_kyber_third_party_poly *r);

// This function assumes a large enough buffer is passed
void br_kyber_third_party_poly_frommsg(br_kyber_third_party_poly *r, const uint8_t *msg);

void br_kyber_third_party_poly_ntt(br_kyber_third_party_poly *r);

void br_kyber_third_party_poly_invntt_tomont(br_kyber_third_party_poly *r);

void br_kyber_third_party_poly_basemul_montgomery(br_kyber_third_party_poly *r, const br_kyber_third_party_poly *a,
                                                  const br_kyber_third_party_poly *b);

void br_kyber_third_party_poly_tomont(br_kyber_third_party_poly *r);

void br_kyber_third_party_poly_reduce(br_kyber_third_party_poly *r);

void br_kyber_third_party_poly_csubq(br_kyber_third_party_poly *r);

void br_kyber_third_party_poly_add(br_kyber_third_party_poly *r, const br_kyber_third_party_poly *a,
                                   const br_kyber_third_party_poly *b);

void br_kyber_third_party_poly_sub(br_kyber_third_party_poly *r, const br_kyber_third_party_poly *a,
                                   const br_kyber_third_party_poly *b);

#endif
