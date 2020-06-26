#ifndef KYBER_REDUCE_H
#define KYBER_REDUCE_H

#include <stdint.h>

#define BR_KYBER_THIRD_PARTY_Q 3329
#define BR_KYBER_THIRD_PARTY_MONT 2285 // 2^16 mod q
#define BR_KYBER_THIRD_PARTY_QINV 62209 // q^-1 mod 2^16

int16_t br_kyber_third_party_montgomery_reduce(int32_t a);

int16_t br_kyber_third_party_barrett_reduce(int16_t a);

int16_t br_kyber_third_party_csubq(int16_t x);

#endif
