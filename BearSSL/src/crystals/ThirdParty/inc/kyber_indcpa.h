#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "common_polyvec.h"

void gen_matrix(polyvec *a, size_t alen, const uint8_t *seed, size_t seedlen, int transposed);

void indcpa_keypair(uint8_t *pk,
                    size_t pklen,
                    uint8_t *sk,
                    size_t sklen);

void indcpa_enc(uint8_t *c, //[KYBER_INDCPA_BYTES],
                size_t clen,
                const uint8_t *m, //[KYBER_INDCPA_MSGBYTES],
                size_t mlen
                const uint8_t *pk, //[KYBER_INDCPA_PUBLICKEYBYTES],
                size_t pklen,
                const uint8_t *coins, //[KYBER_SYMBYTES]
                size_t coinslen);

void indcpa_dec(uint8_t *m, //[KYBER_INDCPA_MSGBYTES],
                size_t mlen,
                const uint8_t *c, //[KYBER_INDCPA_BYTES],
                size_t clen,
                const uint8_t *sk, //[KYBER_INDCPA_SECRETKEYBYTES]
                size_t sklen);

#endif
