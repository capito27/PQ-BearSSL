#ifndef DILITHIUM_REDUCE_H
#define DILITHIUM_REDUCE_H

#include <stdint.h>

#define BR_DILITHIUM_THIRD_PARTY_Q 8380417
#define BR_DILITHIUM_THIRD_PARTY_MONT 4193792U // 2^32 % Q
#define BR_DILITHIUM_THIRD_PARTY_QINV 4236238847U // -q^(-1) mod 2^32

/* a <= Q*2^32 => r < 2*Q */
uint32_t br_dilithium_third_party_montgomery_reduce(uint64_t a);

/* r < 2*Q */
uint32_t br_dilithium_third_party_reduce32(uint32_t a);

/* a < 2*Q => r < Q */
uint32_t br_dilithium_third_party_csubq(uint32_t a);

/* r < Q */
uint32_t br_dilithium_third_party_freeze(uint32_t a);

#endif
