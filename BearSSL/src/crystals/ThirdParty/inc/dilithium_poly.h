#ifndef DILITHIUM_POLY_H
#define DILITHIUM_POLY_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t coeffs[256];
} br_dilithium_third_party_poly __attribute__((aligned(32)));

void br_dilithium_third_party_poly_reduce(br_dilithium_third_party_poly *a);

void br_dilithium_third_party_poly_csubq(br_dilithium_third_party_poly *a);

void br_dilithium_third_party_poly_freeze(br_dilithium_third_party_poly *a);

void br_dilithium_third_party_poly_add(br_dilithium_third_party_poly *c, const br_dilithium_third_party_poly *a,
                                       const br_dilithium_third_party_poly *b);

void br_dilithium_third_party_poly_sub(br_dilithium_third_party_poly *c, const br_dilithium_third_party_poly *a,
                                       const br_dilithium_third_party_poly *b);

void br_dilithium_third_party_poly_shiftl(br_dilithium_third_party_poly *a);

void br_dilithium_third_party_poly_ntt(br_dilithium_third_party_poly *a);

void br_dilithium_third_party_poly_invntt_montgomery(br_dilithium_third_party_poly *a);

void br_dilithium_third_party_poly_pointwise_invmontgomery(br_dilithium_third_party_poly *c,
                                                           const br_dilithium_third_party_poly *a,
                                                           const br_dilithium_third_party_poly *b);

void br_dilithium_third_party_poly_power2round(br_dilithium_third_party_poly *a1, br_dilithium_third_party_poly *a0,
                                               const br_dilithium_third_party_poly *a);

void br_dilithium_third_party_poly_decompose(br_dilithium_third_party_poly *a1, br_dilithium_third_party_poly *a0,
                                             const br_dilithium_third_party_poly *a);

unsigned int br_dilithium_third_party_poly_make_hint(br_dilithium_third_party_poly *h,
                                                     const br_dilithium_third_party_poly *a0,
                                                     const br_dilithium_third_party_poly *a1);

void br_dilithium_third_party_poly_use_hint(br_dilithium_third_party_poly *a, const br_dilithium_third_party_poly *b,
                                            const br_dilithium_third_party_poly *h);

int br_dilithium_third_party_poly_chknorm(const br_dilithium_third_party_poly *a, uint32_t B);

void br_dilithium_third_party_poly_uniform(br_dilithium_third_party_poly *a, const unsigned char *seed, size_t seedlen,
                                           uint16_t nonce);

void br_dilithium_third_party_poly_uniform_eta(br_dilithium_third_party_poly *a, const unsigned char *seed,
                                               size_t seedlen, uint16_t nonce, unsigned eta);


void br_dilithium_third_party_poly_uniform_gamma1m1(br_dilithium_third_party_poly *a, const unsigned char *seed,
                                                    size_t seedlen, uint16_t nonce);

// This function assumes a large enough buffer is passed
void br_dilithium_third_party_polyeta_pack(unsigned char *r, const br_dilithium_third_party_poly *a, unsigned eta);

// This function assumes a large enough buffer is passed
void br_dilithium_third_party_polyeta_unpack(br_dilithium_third_party_poly *r, const unsigned char *a, unsigned eta);

// This function assumes a large enough buffer is passed
void br_dilithium_third_party_polyt1_pack(unsigned char *r, const br_dilithium_third_party_poly *a);

// This function assumes a large enough buffer is passed
void br_dilithium_third_party_polyt1_unpack(br_dilithium_third_party_poly *r, const unsigned char *a);

// This function assumes a large enough buffer is passed
void br_dilithium_third_party_polyt0_pack(unsigned char *r, const br_dilithium_third_party_poly *a);

// This function assumes a large enough buffer is passed
void br_dilithium_third_party_polyt0_unpack(br_dilithium_third_party_poly *r, const unsigned char *a);

// This function assumes a large enough buffer is passed
void br_dilithium_third_party_polyz_pack(unsigned char *r, const br_dilithium_third_party_poly *a);

// This function assumes a large enough buffer is passed
void br_dilithium_third_party_polyz_unpack(br_dilithium_third_party_poly *r, const unsigned char *a);

// This function assumes a large enough buffer is passed
void br_dilithium_third_party_polyw1_pack(unsigned char *r, const br_dilithium_third_party_poly *a);

#endif
