#ifndef DILITHIUM_ROUNDING_H
#define DILITHIUM_ROUNDING_H

#include <stdint.h>
#include "dilithium_reduce.h"

#define BR_DILITHIUM_THIRD_PARTY_D 14
#define BR_DILITHIUM_THIRD_PARTY_GAMMA1 ((BR_DILITHIUM_THIRD_PARTY_Q - 1)/16)
#define BR_DILITHIUM_THIRD_PARTY_GAMMA2 (BR_DILITHIUM_THIRD_PARTY_GAMMA1/2)
#define BR_DILITHIUM_THIRD_PARTY_ALPHA (2*BR_DILITHIUM_THIRD_PARTY_GAMMA2)

uint32_t br_dilithium_third_party_power2round(const uint32_t a, uint32_t *a0);

uint32_t br_dilithium_third_party_decompose(uint32_t a, uint32_t *a0);

unsigned int br_dilithium_third_party_make_hint(const uint32_t a0, const uint32_t a1);

uint32_t br_dilithium_third_party_use_hint(const uint32_t a, const unsigned int hint);

#endif
