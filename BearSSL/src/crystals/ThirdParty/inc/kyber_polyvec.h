#ifndef KYBER_POLYVEC_H
#define KYBER_POLYVEC_H

#include <stdint.h>
#include "kyber_poly.h"

typedef struct {
    br_kyber_third_party_poly *vec;
    size_t veclen; // number of poly in vector, not bytes
} br_kyber_third_party_polyvec;

void br_kyber_third_party_polyvec_compress(uint8_t *r, unsigned polynbr, br_kyber_third_party_polyvec *a);

void br_kyber_third_party_polyvec_decompress(br_kyber_third_party_polyvec *r, const uint8_t *a, unsigned polynbr);

// This function assumes a large enough buffer is passed
void br_kyber_third_party_polyvec_tobytes(uint8_t *r, br_kyber_third_party_polyvec *a);

// This function assumes a large enough buffer is passed
void br_kyber_third_party_polyvec_frombytes(br_kyber_third_party_polyvec *r, const uint8_t *a);

void br_kyber_third_party_polyvec_ntt(br_kyber_third_party_polyvec *r);

void br_kyber_third_party_polyvec_invntt_tomont(br_kyber_third_party_polyvec *r);

void br_kyber_third_party_polyvec_pointwise_acc_montgomery(br_kyber_third_party_poly *r,
                                                           const br_kyber_third_party_polyvec *a,
                                                           const br_kyber_third_party_polyvec *b);

void br_kyber_third_party_polyvec_reduce(br_kyber_third_party_polyvec *r);

void br_kyber_third_party_polyvec_csubq(br_kyber_third_party_polyvec *r);

void br_kyber_third_party_polyvec_add(br_kyber_third_party_polyvec *r, const br_kyber_third_party_polyvec *a, const br_kyber_third_party_polyvec *b);

#endif
