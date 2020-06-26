#ifndef DILITHIUM_POLYVEC_H
#define DILITHIUM_POLYVEC_H

#include <stdint.h>
#include <stddef.h>
#include "dilithium_poly.h"

/* Vectors of polynomials */
typedef struct {
    br_dilithium_third_party_poly *vec;
    size_t polylen; // size of vector, in number of polynomials
} br_dilithium_third_party_polyvec;

void br_dilithium_third_party_polyvec_freeze(br_dilithium_third_party_polyvec *v);

void br_dilithium_third_party_polyvec_add(br_dilithium_third_party_polyvec *w,
                                          const br_dilithium_third_party_polyvec *u,
                                          const br_dilithium_third_party_polyvec *v);

void br_dilithium_third_party_polyvec_sub(br_dilithium_third_party_polyvec *w,
                                          const br_dilithium_third_party_polyvec *u,
                                          const br_dilithium_third_party_polyvec *v);

void br_dilithium_third_party_polyvec_ntt(br_dilithium_third_party_polyvec *v);

void br_dilithium_third_party_polyvec_pointwise_acc_invmontgomery(br_dilithium_third_party_poly *w,
                                                                  const br_dilithium_third_party_polyvec *u,
                                                                  const br_dilithium_third_party_polyvec *v);

int br_dilithium_third_party_polyvec_chknorm(const br_dilithium_third_party_polyvec *v, uint32_t B);

void br_dilithium_third_party_polyvec_reduce(br_dilithium_third_party_polyvec *v);

void br_dilithium_third_party_polyvec_csubq(br_dilithium_third_party_polyvec *v);

void br_dilithium_third_party_polyvec_shiftl(br_dilithium_third_party_polyvec *v);

void br_dilithium_third_party_polyvec_invntt_montgomery(br_dilithium_third_party_polyvec *v);

void br_dilithium_third_party_polyvec_power2round(br_dilithium_third_party_polyvec *v1,
                                                  br_dilithium_third_party_polyvec *v0,
                                                  const br_dilithium_third_party_polyvec *v);

void br_dilithium_third_party_polyvec_decompose(br_dilithium_third_party_polyvec *v1,
                                                br_dilithium_third_party_polyvec *v0,
                                                const br_dilithium_third_party_polyvec *v);

unsigned int br_dilithium_third_party_polyvec_make_hint(br_dilithium_third_party_polyvec *h,
                                                        const br_dilithium_third_party_polyvec *v0,
                                                        const br_dilithium_third_party_polyvec *v1);

void br_dilithium_third_party_polyvec_use_hint(br_dilithium_third_party_polyvec *w,
                                               const br_dilithium_third_party_polyvec *v,
                                               const br_dilithium_third_party_polyvec *h);

#endif
