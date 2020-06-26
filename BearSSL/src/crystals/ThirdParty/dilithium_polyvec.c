#include <stdint.h>
#include "inc/dilithium_poly.h"
#include "inc/dilithium_polyvec.h"

/*************************************************
* Name:        polyvec_freeze
*
* Description: Reduce coefficients of polynomials in vector
*              to standard representatives.
*
* Arguments:   - polyvec *v: pointer to input/output vector
**************************************************/
void br_dilithium_third_party_polyvec_freeze(br_dilithium_third_party_polyvec *v) {
    unsigned int i;

    for (i = 0; i < v->polylen; ++i)
        br_dilithium_third_party_poly_freeze(&v->vec[i]);
}

/*************************************************
* Name:        polyvec_add
*
* Description: Add vectors of polynomials of same length.
*              No modular reduction is performed.
*
* Arguments:   - polyvec *w: pointer to output vector
*              - const polyvec *u: pointer to first summand
*              - const polyvec *v: pointer to second summand
**************************************************/
void br_dilithium_third_party_polyvec_add(br_dilithium_third_party_polyvec *w,
                                          const br_dilithium_third_party_polyvec *u,
                                          const br_dilithium_third_party_polyvec *v) {
    unsigned int i;

    for (i = 0; i < w->polylen; ++i)
        br_dilithium_third_party_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyvec_sub
*
* Description: Subtract vectors of polynomials.
*              Assumes coefficients of polynomials in second input vector
*              to be less than 2*Q. No modular reduction is performed.
*
* Arguments:   - polyvec *w: pointer to output vector
*              - const polyvec *u: pointer to first input vector
*              - const polyvec *v: pointer to second input vector to be
*                                   subtracted from first input vector
**************************************************/
void br_dilithium_third_party_polyvec_sub(br_dilithium_third_party_polyvec *w,
                                          const br_dilithium_third_party_polyvec *u,
                                          const br_dilithium_third_party_polyvec *v) {
    unsigned int i;

    for (i = 0; i < w->polylen; ++i)
        br_dilithium_third_party_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyvec_ntt
*
* Description: Forward NTT of all polynomials in vector. Output
*              coefficients can be up to 16*Q larger than input coefficients.
*
* Arguments:   - polyvec *v: pointer to input/output vector
**************************************************/
void br_dilithium_third_party_polyvec_ntt(br_dilithium_third_party_polyvec *v) {
    unsigned int i;

    for (i = 0; i < v->polylen; ++i)
        br_dilithium_third_party_poly_ntt(&v->vec[i]);
}

/*************************************************
* Name:        polyvec_pointwise_acc_invmontgomery
*
* Description: Pointwise multiply vectors of polynomials, multiply
*              resulting vector by 2^{-32} and add (accumulate) polynomials
*              in it. Input/output vectors are in NTT domain representation.
*              Input coefficients are assumed to be less than 22*Q. Output
*              coeffcient are less than 2*L*Q.
*
* Arguments:   - poly *w: output polynomial
*              - const polyvec *u: pointer to first input vector
*              - const polyvec *v: pointer to second input vector
**************************************************/
void br_dilithium_third_party_polyvec_pointwise_acc_invmontgomery(br_dilithium_third_party_poly *w,
                                                                  const br_dilithium_third_party_polyvec *u,
                                                                  const br_dilithium_third_party_polyvec *v) {
    unsigned int i;
    br_dilithium_third_party_poly t;

    br_dilithium_third_party_poly_pointwise_invmontgomery(w, &u->vec[0], &v->vec[0]);

    for (i = 1; i < u->polylen; ++i) {
        br_dilithium_third_party_poly_pointwise_invmontgomery(&t, &u->vec[i], &v->vec[i]);
        br_dilithium_third_party_poly_add(w, w, &t);
    }
}

/*************************************************
* Name:        polyvec_chknorm
*
* Description: Check infinity norm of polynomials in vector of length L.
*              Assumes input coefficients to be standard representatives.
*
* Arguments:   - const polyvec *v: pointer to vector
*              - uint32_t B: norm bound
*
* Returns 0 if norm of all polynomials is strictly smaller than B and 1
* otherwise.
**************************************************/
int br_dilithium_third_party_polyvec_chknorm(const br_dilithium_third_party_polyvec *v, uint32_t bound) {
    unsigned int i;

    for (i = 0; i < v->polylen; ++i)
        if (br_dilithium_third_party_poly_chknorm(&v->vec[i], bound))
            return 1;

    return 0;
}

/*************************************************
* Name:        polyvec_reduce
*
* Description: Reduce coefficients of polynomials in vector
*              to representatives in [0,2*Q[.
*
* Arguments:   - polyvec *v: pointer to input/output vector
**************************************************/
void br_dilithium_third_party_polyvec_reduce(br_dilithium_third_party_polyvec *v) {
    unsigned int i;

    for (i = 0; i < v->polylen; ++i)
        br_dilithium_third_party_poly_reduce(&v->vec[i]);
}

/*************************************************
* Name:        polyvec_csubq
*
* Description: For all coefficients of polynomials in vector
*              subtract Q if coefficient is bigger than Q.
*
* Arguments:   - polyvec *v: pointer to input/output vector
**************************************************/
void br_dilithium_third_party_polyvec_csubq(br_dilithium_third_party_polyvec *v) {
    unsigned int i;

    for (i = 0; i < v->polylen; ++i)
        br_dilithium_third_party_poly_csubq(&v->vec[i]);
}

/*************************************************
* Name:        polyvec_shiftl
*
* Description: Multiply vector of polynomials by 2^D without modular
*              reduction. Assumes input coefficients to be less than 2^{32-D}.
*
* Arguments:   - polyvec *v: pointer to input/output vector
**************************************************/
void br_dilithium_third_party_polyvec_shiftl(br_dilithium_third_party_polyvec *v) {
    unsigned int i;

    for (i = 0; i < v->polylen; ++i)
        br_dilithium_third_party_poly_shiftl(&v->vec[i]);
}


/*************************************************
* Name:        polyvec_invntt_montgomery
*
* Description: Inverse NTT and multiplication by 2^{32} of polynomials
*              in vector. Input coefficients need to be less
*              than 2*Q.
*
* Arguments:   - polyvec *v: pointer to input/output vector
**************************************************/
void br_dilithium_third_party_polyvec_invntt_montgomery(br_dilithium_third_party_polyvec *v) {
    unsigned int i;

    for (i = 0; i < v->polylen; ++i)
        br_dilithium_third_party_poly_invntt_montgomery(&v->vec[i]);
}

/*************************************************
* Name:        polyvec_power2round
*
* Description: For all coefficients a of polynomials in vector,
*              compute a0, a1 such that a mod Q = a1*2^D + a0
*              with -2^{D-1} < a0 <= 2^{D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - polyvec *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - polyvec *v0: pointer to output vector of polynomials with
*                              coefficients Q + a0
*              - const polyvec *v: pointer to input vector
**************************************************/
void br_dilithium_third_party_polyvec_power2round(br_dilithium_third_party_polyvec *v1,
                                                  br_dilithium_third_party_polyvec *v0,
                                                  const br_dilithium_third_party_polyvec *v) {
    unsigned int i;

    for (i = 0; i < v1->polylen; ++i)
        br_dilithium_third_party_poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyvec_decompose
*
* Description: For all coefficients a of polynomials in vector,
*              compute high and low bits a0, a1 such a mod Q = a1*ALPHA + a0
*              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q-1)/ALPHA where we
*              set a1 = 0 and -ALPHA/2 <= a0 = a mod Q - Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - polyvec *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - polyvec *v0: pointer to output vector of polynomials with
*                              coefficients Q + a0
*              - const polyvec *v: pointer to input vector
**************************************************/
void br_dilithium_third_party_polyvec_decompose(br_dilithium_third_party_polyvec *v1,
                                                br_dilithium_third_party_polyvec *v0,
                                                const br_dilithium_third_party_polyvec *v) {
    unsigned int i;

    for (i = 0; i < v1->polylen; ++i)
        br_dilithium_third_party_poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyvec_make_hint
*
* Description: Compute hint vector.
*
* Arguments:   - polyvec *h: pointer to output vector
*              - const polyvec *v0: pointer to low part of input vector
*              - const polyvec *v1: pointer to high part of input vector
*
* Returns number of 1 bits.
**************************************************/
unsigned int br_dilithium_third_party_polyvec_make_hint(br_dilithium_third_party_polyvec *h,
                                                        const br_dilithium_third_party_polyvec *v0,
                                                        const br_dilithium_third_party_polyvec *v1) {
    unsigned int i, s = 0;

    for (i = 0; i < h->polylen; ++i)
        s += br_dilithium_third_party_poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);

    return s;
}

/*************************************************
* Name:        polyveck_use_hint
*
* Description: Use hint vector to correct the high bits of input vector.
*
* Arguments:   - polyveck *w: pointer to output vector of polynomials with
*                             corrected high bits
*              - const polyveck *u: pointer to input vector
*              - const polyveck *h: pointer to input hint vector
**************************************************/
void br_dilithium_third_party_polyvec_use_hint(br_dilithium_third_party_polyvec *w,
                                               const br_dilithium_third_party_polyvec *u,
                                               const br_dilithium_third_party_polyvec *h) {
    unsigned int i;

    for (i = 0; i < w->polylen; ++i)
        br_dilithium_third_party_poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
}
