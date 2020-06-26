#include <stdint.h>
#include "inc/dilithium_reduce.h"

/*************************************************
* Name:        montgomery_reduce
*
* Description: For finite field element a with 0 <= a <= Q*2^32,
*              compute r \equiv a*2^{-32} (mod Q) such that 0 <= r < 2*Q.
*
* Arguments:   - uint64_t: finite field element a
*
* Returns r.
**************************************************/
uint32_t br_dilithium_third_party_montgomery_reduce(uint64_t a) {
  uint64_t t;

  t = a * BR_DILITHIUM_THIRD_PARTY_QINV;
  t &= (1ULL << 32) - 1;
  t *= BR_DILITHIUM_THIRD_PARTY_Q;
  t = a + t;
  t >>= 32;
  return t;
}

/*************************************************
* Name:        reduce32
*
* Description: For finite field element a, compute r \equiv a (mod Q)
*              such that 0 <= r < 2*Q.
*
* Arguments:   - uint32_t: finite field element a
*
* Returns r.
**************************************************/
uint32_t br_dilithium_third_party_reduce32(uint32_t a) {
  uint32_t t;

  t = a & 0x7FFFFF;
  a >>= 23;
  t += (a << 13) - a;
  return t;
}

/*************************************************
* Name:        csubq
*
* Description: Subtract Q if input coefficient is bigger than Q.
*
* Arguments:   - uint32_t: finite field element a
*
* Returns r.
**************************************************/
uint32_t br_dilithium_third_party_csubq(uint32_t a) {
  a -= BR_DILITHIUM_THIRD_PARTY_Q;
  a += ((int32_t)a >> 31) & BR_DILITHIUM_THIRD_PARTY_Q;
  return a;
}

/*************************************************
* Name:        freeze
*
* Description: For finite field element a, compute standard
*              representative r = a mod Q.
*
* Arguments:   - uint32_t: finite field element a
*
* Returns r.
**************************************************/
uint32_t br_dilithium_third_party_freeze(uint32_t a) {
  a = br_dilithium_third_party_reduce32(a);
  a = br_dilithium_third_party_csubq(a);
  return a;
}
