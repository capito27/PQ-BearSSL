#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "common_poly.h"

typedef struct{
  poly *vec;
  size_t veclen; // in number of poly in vector, not bytes
} polyvec;

void polyvec_compress(uint8_t *r, size_t rlen, polyvec *a);
void polyvec_decompress(polyvec *r, const uint8_t *a, size_t alen);

void polyvec_tobytes(uint8_t *r, size_t rlen, polyvec *a);
void polyvec_frombytes(polyvec *r, const uint8_t *a, size_t alen);

void polyvec_ntt(polyvec *r);
void polyvec_invntt_tomont(polyvec *r);

void polyvec_pointwise_acc_montgomery(poly *r,
                                      const polyvec *a,
                                      const polyvec *b);

void polyvec_reduce(polyvec *r);
void polyvec_csubq(polyvec *r);

void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);

#endif
