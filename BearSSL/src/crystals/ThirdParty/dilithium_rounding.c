#include <stdint.h>

#include "inc/dilithium_rounding.h"

/*************************************************
* Name:        power2round
*
* Description: For finite field element a, compute a0, a1 such that
*              a mod Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
*              Assumes a to be standard representative.
*
* Arguments:   - uint32_t a: input element
*              - uint32_t *a0: pointer to output element Q + a0
*
* Returns a1.
**************************************************/
uint32_t br_dilithium_third_party_power2round(uint32_t a, uint32_t *a0) {
    int32_t t;

    /* Centralized remainder mod 2^D */
    t = a & ((1U << BR_DILITHIUM_THIRD_PARTY_D) - 1);
    t -= (1U << (BR_DILITHIUM_THIRD_PARTY_D - 1)) + 1;
    t += (t >> 31) & (1U << BR_DILITHIUM_THIRD_PARTY_D);
    t -= (1U << (BR_DILITHIUM_THIRD_PARTY_D - 1)) - 1;
    *a0 = BR_DILITHIUM_THIRD_PARTY_Q + t;
    a = (a - t) >> BR_DILITHIUM_THIRD_PARTY_D;
    return a;
}

/*************************************************
* Name:        decompose
*
* Description: For finite field element a, compute high and low bits a0, a1 such
*              that a mod Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except
*              if a1 = (Q-1)/ALPHA where we set a1 = 0 and
*              -ALPHA/2 <= a0 = a mod Q - Q < 0. Assumes a to be standard
*              representative.
*
* Arguments:   - uint32_t a: input element
*              - uint32_t *a0: pointer to output element Q + a0
*
* Returns a1.
**************************************************/
uint32_t br_dilithium_third_party_decompose(uint32_t a, uint32_t *a0) {
    int32_t t, u;

    /* Centralized remainder mod ALPHA */
    t = a & 0x7FFFF;
    t += (a >> 19) << 9;
    t -= BR_DILITHIUM_THIRD_PARTY_ALPHA / 2 + 1;
    t += (t >> 31) & BR_DILITHIUM_THIRD_PARTY_ALPHA;
    t -= BR_DILITHIUM_THIRD_PARTY_ALPHA / 2 - 1;
    a -= t;

    /* Divide by ALPHA (possible to avoid) */
    u = a - 1;
    u >>= 31;
    a = (a >> 19) + 1;
    a -= u & 1;

    /* Border case */

    *a0 = BR_DILITHIUM_THIRD_PARTY_Q + t - (a >> 4);
    a &= 0xF;
    return a;
}

/*************************************************
* Name:        make_hint
*
* Description: Compute hint bit indicating whether the low bits of the
*              input element overflow into the high bits. Inputs assumed to be
*              standard representatives.
*
* Arguments:   - uint32_t a0: low bits of input element
*              - uint32_t a1: high bits of input element
*
* Returns 1 if high bits of a and b differ and 0 otherwise.
**************************************************/
unsigned int br_dilithium_third_party_make_hint(const uint32_t a0, const uint32_t a1) {
    if (a0 <= BR_DILITHIUM_THIRD_PARTY_GAMMA2 || a0 > BR_DILITHIUM_THIRD_PARTY_Q - BR_DILITHIUM_THIRD_PARTY_GAMMA2 ||
        (a0 == BR_DILITHIUM_THIRD_PARTY_Q - BR_DILITHIUM_THIRD_PARTY_GAMMA2 && a1 == 0))
        return 0;

    return 1;
}

/*************************************************
* Name:        use_hint
*
* Description: Correct high bits according to hint.
*
* Arguments:   - uint32_t a: input element
*              - unsigned int hint: hint bit
*
* Returns corrected high bits.
**************************************************/
uint32_t br_dilithium_third_party_use_hint(const uint32_t a, const unsigned int hint) {
    uint32_t a0, a1;

    a1 = br_dilithium_third_party_decompose(a, &a0);
    if (hint == 0)
        return a1;
    else if (a0 > BR_DILITHIUM_THIRD_PARTY_Q)
        return (a1 + 1) & 0xF;
    else
        return (a1 - 1) & 0xF;

    /* If decompose does not divide out ALPHA:
    if(hint == 0)
      return a1;
    else if(a0 > Q)
      return (a1 + ALPHA) % (Q - 1);
    else
      return (a1 - ALPHA) % (Q - 1);
    */
}
