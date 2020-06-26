#ifndef KYBER_NTT_H
#define KYBER_NTT_H

#include <stdint.h>
#include <stddef.h>

extern const int16_t br_kyber_third_party_zetas[128];

extern const int16_t br_kyber_third_party_zetas_inv[128];

void br_kyber_third_party_ntt(int16_t *poly, size_t polylen);

void br_kyber_third_party_invntt(int16_t *poly, size_t polylen);

void br_kyber_third_party_basemul(int16_t r[2],
                                  const int16_t a[2],
                                  const int16_t b[2],
                                  int16_t zeta);

#endif
