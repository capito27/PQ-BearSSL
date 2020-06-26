#include <stdint.h>
#include "inner.h"
#include "inc/dilithium_ntt.h"
#include "inc/dilithium_reduce.h"
#include "inc/dilithium_rounding.h"
#include "inc/dilithium_poly.h"

/*************************************************
* Name:        poly_reduce
*
* Description: Reduce all coefficients of input polynomial to representative
*              in [0,2*Q[.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void br_dilithium_third_party_poly_reduce(br_dilithium_third_party_poly *a) {
    unsigned int i;

    for (i = 0; i < sizeof(a->coeffs) / sizeof(a->coeffs[0]); ++i)
        a->coeffs[i] = br_dilithium_third_party_reduce32(a->coeffs[i]);

}

/*************************************************
* Name:        poly_csubq
*
* Description: For all coefficients of input polynomial subtract Q if
*              coefficient is bigger than Q.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void br_dilithium_third_party_poly_csubq(br_dilithium_third_party_poly *a) {
    unsigned int i;

    for (i = 0; i < sizeof(a->coeffs) / sizeof(a->coeffs[0]); ++i)
        a->coeffs[i] = br_dilithium_third_party_csubq(a->coeffs[i]);
}

/*************************************************
* Name:        poly_freeze
*
* Description: Reduce all coefficients of the polynomial to standard
*              representatives.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void br_dilithium_third_party_poly_freeze(br_dilithium_third_party_poly *a) {
    unsigned int i;

    for (i = 0; i < sizeof(a->coeffs) / sizeof(a->coeffs[0]); ++i)
        a->coeffs[i] = br_dilithium_third_party_freeze(a->coeffs[i]);
}

/*************************************************
* Name:        poly_add
*
* Description: Add polynomials. No modular reduction is performed.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first summand
*              - const poly *b: pointer to second summand
**************************************************/
void br_dilithium_third_party_poly_add(br_dilithium_third_party_poly *c, const br_dilithium_third_party_poly *a,
                                       const br_dilithium_third_party_poly *b) {
    unsigned int i;

    for (i = 0; i < sizeof(c->coeffs) / sizeof(c->coeffs[0]); ++i)
        c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

/*************************************************
* Name:        poly_sub
*
* Description: Subtract polynomials. Assumes coefficients of second input
*              polynomial to be less than 2*Q. No modular reduction is
*              performed.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial to be
*                               subtraced from first input polynomial
**************************************************/
void br_dilithium_third_party_poly_sub(br_dilithium_third_party_poly *c, const br_dilithium_third_party_poly *a,
                                       const br_dilithium_third_party_poly *b) {
    unsigned int i;

    for (i = 0; i < sizeof(c->coeffs) / sizeof(c->coeffs[0]); ++i)
        c->coeffs[i] = a->coeffs[i] + 2 * BR_DILITHIUM_THIRD_PARTY_Q - b->coeffs[i];
}

/*************************************************
* Name:        poly_shiftl
*
* Description: Multiply polynomial by 2^D without modular reduction. Assumes
*              input coefficients to be less than 2^{32-D}.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void br_dilithium_third_party_poly_shiftl(br_dilithium_third_party_poly *a) {
    unsigned int i;

    for (i = 0; i < sizeof(a->coeffs) / sizeof(a->coeffs[0]); ++i)
        a->coeffs[i] <<= BR_DILITHIUM_THIRD_PARTY_D;
}

/*************************************************
* Name:        poly_ntt
*
* Description: Forward NTT. Output coefficients can be up to 16*Q larger than
*              input coefficients.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void br_dilithium_third_party_poly_ntt(br_dilithium_third_party_poly *a) {
    br_dilithium_third_party_ntt(a->coeffs, sizeof(a->coeffs) / sizeof(a->coeffs[0]));
}

/*************************************************
* Name:        poly_invntt_montgomery
*
* Description: Inverse NTT and multiplication with 2^{32}. Input coefficients
*              need to be less than 2*Q. Output coefficients are less than 2*Q.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void br_dilithium_third_party_poly_invntt_montgomery(br_dilithium_third_party_poly *a) {
    br_dilithium_third_party_invntt_frominvmont(a->coeffs, sizeof(a->coeffs) / sizeof(a->coeffs[0]));
}

/*************************************************
* Name:        poly_pointwise_invmontgomery
*
* Description: Pointwise multiplication of polynomials in NTT domain
*              representation and multiplication of resulting polynomial
*              with 2^{-32}. Output coefficients are less than 2*Q if input
*              coefficient are less than 22*Q.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void br_dilithium_third_party_poly_pointwise_invmontgomery(br_dilithium_third_party_poly *c,
                                                           const br_dilithium_third_party_poly *a,
                                                           const br_dilithium_third_party_poly *b) {
    unsigned int i;

    for (i = 0; i < sizeof(c->coeffs) / sizeof(c->coeffs[0]); ++i)
        c->coeffs[i] = br_dilithium_third_party_montgomery_reduce((uint64_t) a->coeffs[i] * b->coeffs[i]);
}

/*************************************************
* Name:        poly_power2round
*
* Description: For all coefficients c of the input polynomial,
*              compute c0, c1 such that c mod Q = c1*2^D + c0
*              with -2^{D-1} < c0 <= 2^{D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - poly *a1: pointer to output polynomial with coefficients c1
*              - poly *a0: pointer to output polynomial with coefficients Q + a0
*              - const poly *v: pointer to input polynomial
**************************************************/
void br_dilithium_third_party_poly_power2round(br_dilithium_third_party_poly *a1, br_dilithium_third_party_poly *a0,
                                               const br_dilithium_third_party_poly *a) {
    unsigned int i;

    for (i = 0; i < sizeof(a1->coeffs) / sizeof(a1->coeffs[0]); ++i)
        a1->coeffs[i] = br_dilithium_third_party_power2round(a->coeffs[i], &a0->coeffs[i]);
}

/*************************************************
* Name:        poly_decompose
*
* Description: For all coefficients c of the input polynomial,
*              compute high and low bits c0, c1 such c mod Q = c1*ALPHA + c0
*              with -ALPHA/2 < c0 <= ALPHA/2 except c1 = (Q-1)/ALPHA where we
*              set c1 = 0 and -ALPHA/2 <= c0 = c mod Q - Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - poly *a1: pointer to output polynomial with coefficients c1
*              - poly *a0: pointer to output polynomial with coefficients Q + a0
*              - const poly *c: pointer to input polynomial
**************************************************/
void br_dilithium_third_party_poly_decompose(br_dilithium_third_party_poly *a1, br_dilithium_third_party_poly *a0,
                                             const br_dilithium_third_party_poly *a) {
    unsigned int i;

    for (i = 0; i < sizeof(a1->coeffs) / sizeof(a1->coeffs[0]); ++i)
        a1->coeffs[i] = br_dilithium_third_party_decompose(a->coeffs[i], &a0->coeffs[i]);
}

/*************************************************
* Name:        poly_make_hint
*
* Description: Compute hint polynomial. The coefficients of which indicate
*              whether the low bits of the corresponding coefficient of
*              the input polynomial overflow into the high bits.
*
* Arguments:   - poly *h: pointer to output hint polynomial
*              - const poly *a0: pointer to low part of input polynomial
*              - const poly *a1: pointer to high part of input polynomial
*
* Returns number of 1 bits.
**************************************************/
unsigned int
br_dilithium_third_party_poly_make_hint(br_dilithium_third_party_poly *h, const br_dilithium_third_party_poly *a0,
                                        const br_dilithium_third_party_poly *a1) {
    unsigned int i, s = 0;

    for (i = 0; i < sizeof(h->coeffs) / sizeof(h->coeffs[0]); ++i) {
        h->coeffs[i] = br_dilithium_third_party_make_hint(a0->coeffs[i], a1->coeffs[i]);
        s += h->coeffs[i];
    }
    return s;
}

/*************************************************
* Name:        poly_use_hint
*
* Description: Use hint polynomial to correct the high bits of a polynomial.
*
* Arguments:   - poly *a: pointer to output polynomial with corrected high bits
*              - const poly *b: pointer to input polynomial
*              - const poly *h: pointer to input hint polynomial
**************************************************/
void br_dilithium_third_party_poly_use_hint(br_dilithium_third_party_poly *a, const br_dilithium_third_party_poly *b,
                                            const br_dilithium_third_party_poly *h) {
    unsigned int i;

    for (i = 0; i < sizeof(a->coeffs) / sizeof(a->coeffs[0]); ++i)
        a->coeffs[i] = br_dilithium_third_party_use_hint(b->coeffs[i], h->coeffs[i]);
}

/*************************************************
* Name:        poly_chknorm
*
* Description: Check infinity norm of polynomial against given bound.
*              Assumes input coefficients to be standard representatives.
*
* Arguments:   - const poly *a: pointer to polynomial
*              - uint32_t B: norm bound
*
* Returns 0 if norm is strictly smaller than B and 1 otherwise.
**************************************************/
int br_dilithium_third_party_poly_chknorm(const br_dilithium_third_party_poly *a, uint32_t B) {
    unsigned int i;
    int32_t t;

    /* It is ok to leak which coefficient violates the bound since
       the probability for each coefficient is independent of secret
       data but we must not leak the sign of the centralized representative. */
    for (i = 0; i < sizeof(a->coeffs) / sizeof(a->coeffs[0]); ++i) {
        /* Absolute value of centralized representative */
        t = (BR_DILITHIUM_THIRD_PARTY_Q - 1) / 2 - a->coeffs[i];
        t ^= (t >> 31);
        t = (BR_DILITHIUM_THIRD_PARTY_Q - 1) / 2 - t;

        if ((uint32_t) t >= B) {
            return 1;
        }
    }
    return 0;
}

/*************************************************
* Name:        rej_uniform
*
* Description: Sample uniformly random coefficients in [0, Q-1] by
*              performing rejection sampling using array of random bytes.
*
* Arguments:   - uint32_t *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const unsigned char *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static unsigned int rej_uniform(uint32_t *a,
                                unsigned int len,
                                const unsigned char *buf,
                                unsigned int buflen) {
    unsigned int ctr, pos;
    uint32_t t;

    ctr = pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        t = buf[pos++];
        t |= (uint32_t) buf[pos++] << 8;
        t |= (uint32_t) buf[pos++] << 16;
        t &= 0x7FFFFF;

        if (t < BR_DILITHIUM_THIRD_PARTY_Q)
            a[ctr++] = t;
    }
    return ctr;
}

/*************************************************
* Name:        poly_uniform
*
* Description: Sample polynomial with uniformly random coefficients
*              in [0,Q-1] by performing rejection sampling using the
*              output stream from SHAKE256(seed|nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const unsigned char seed[]: byte array with seed of length
*                                            SEEDBYTES
*              - uint16_t nonce: 2-byte nonce
**************************************************/
void br_dilithium_third_party_poly_uniform(br_dilithium_third_party_poly *a, const unsigned char *seed, size_t seedlen,
                                           uint16_t nonce) {
    unsigned int i, ctr, off;
    unsigned int nblocks = (769 + 168) / 168; // 168 = shake128 rate in bytes
    unsigned int buflen = nblocks * 168;
    unsigned char buf[buflen + 2];
    br_shake_context sc;

    br_shake_init(&sc, 128);
    br_shake_inject(&sc, seed, seedlen);
    br_shake_inject(&sc, &nonce, sizeof(nonce));
    br_shake_flip(&sc, 0);
    br_shake_produce(&sc, buf, buflen);

    ctr = rej_uniform(a->coeffs, sizeof(a->coeffs) / sizeof(a->coeffs[0]), buf, buflen);

    while (ctr < sizeof(a->coeffs) / sizeof(a->coeffs[0])) {
        off = buflen % 3;
        for (i = 0; i < off; ++i)
            buf[i] = buf[buflen - off + i];

        buflen = 168 + off;
        br_shake_produce(&sc, buf + off, 1);
        ctr += rej_uniform(a->coeffs + ctr, sizeof(a->coeffs) / sizeof(a->coeffs[0]) - ctr, buf, buflen);
    }
}

/*************************************************
* Name:        rej_eta
*
* Description: Sample uniformly random coefficients in [-ETA, ETA] by
*              performing rejection sampling using array of random bytes.
*
* Arguments:   - uint32_t *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const unsigned char *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static unsigned int rej_eta(uint32_t *a,
                            unsigned int len,
                            const unsigned char *buf,
                            unsigned int buflen, unsigned eta) {
    unsigned int ctr, pos;
    uint32_t t0, t1;

    ctr = pos = 0;
    while (ctr < len && pos < buflen) {
        if (eta <= 3) {
            t0 = buf[pos] & 0x07;
            t1 = buf[pos++] >> 5;
        } else {
            t0 = buf[pos] & 0x0F;
            t1 = buf[pos++] >> 4;
        }

        if (t0 <= 2 * eta)
            a[ctr++] = BR_DILITHIUM_THIRD_PARTY_Q + eta - t0;
        if (t1 <= 2 * eta && ctr < len)
            a[ctr++] = BR_DILITHIUM_THIRD_PARTY_Q + eta - t1;
    }
    return ctr;
}

/*************************************************
* Name:        poly_uniform_eta
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-ETA,ETA] by performing rejection sampling using the
*              output stream from SHAKE256(seed|nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const unsigned char seed[]: byte array with seed of length
*                                            SEEDBYTES
*              - uint16_t nonce: 2-byte nonce
**************************************************/
void br_dilithium_third_party_poly_uniform_eta(br_dilithium_third_party_poly *a, const unsigned char *seed,
                                               size_t seedlen, uint16_t nonce, unsigned eta) {
    unsigned int ctr;
    unsigned int nblocks = ((256 / 2 * (1U << (eta <= 3 ? 3 : 4))) / (2 * eta + 1) + 168) / 168;

    unsigned int buflen = nblocks * 168;

    unsigned char buf[buflen];
    br_shake_context sc;

    br_shake_init(&sc, 128);
    br_shake_inject(&sc, seed, seedlen);
    br_shake_inject(&sc, &nonce, sizeof(nonce));
    br_shake_flip(&sc, 0);
    br_shake_produce(&sc, buf, buflen);

    ctr = rej_eta(a->coeffs, sizeof(a->coeffs) / sizeof(a->coeffs[0]), buf, buflen, eta);

    while (ctr < sizeof(a->coeffs) / sizeof(a->coeffs[0])) {
        br_shake_produce(&sc, buf, 1);
        ctr += rej_eta(a->coeffs + ctr, sizeof(a->coeffs) / sizeof(a->coeffs[0]) - ctr, buf, 168, eta);
    }
}

/*************************************************
* Name:        rej_gamma1m1
*
* Description: Sample uniformly random coefficients
*              in [-(GAMMA1 - 1), GAMMA1 - 1] by performing rejection sampling
*              using array of random bytes.
*
* Arguments:   - uint32_t *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const unsigned char *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static unsigned int rej_gamma1m1(uint32_t *a,
                                 unsigned int len,
                                 const unsigned char *buf,
                                 unsigned int buflen) {
    unsigned int ctr, pos;
    uint32_t t0, t1;

    ctr = pos = 0;
    while (ctr < len && pos + 5 <= buflen) {
        t0 = buf[pos];
        t0 |= (uint32_t) buf[pos + 1] << 8;
        t0 |= (uint32_t) buf[pos + 2] << 16;
        t0 &= 0xFFFFF;

        t1 = buf[pos + 2] >> 4;
        t1 |= (uint32_t) buf[pos + 3] << 4;
        t1 |= (uint32_t) buf[pos + 4] << 12;

        pos += 5;

        if (t0 <= 2 * BR_DILITHIUM_THIRD_PARTY_GAMMA1 - 2)
            a[ctr++] = BR_DILITHIUM_THIRD_PARTY_Q + BR_DILITHIUM_THIRD_PARTY_GAMMA1 - 1 - t0;
        if (t1 <= 2 * BR_DILITHIUM_THIRD_PARTY_GAMMA1 - 2 && ctr < len)
            a[ctr++] = BR_DILITHIUM_THIRD_PARTY_Q + BR_DILITHIUM_THIRD_PARTY_GAMMA1 - 1 - t1;
    }
    return ctr;
}

/*************************************************
* Name:        poly_uniform_gamma1m1
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-(GAMMA1 - 1), GAMMA1 - 1] by performing rejection
*              sampling on output stream of SHAKE256(seed|nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const unsigned char seed[]: byte array with seed of length
*                                            CRHBYTES
*              - uint16_t nonce: 16-bit nonce
**************************************************/
void br_dilithium_third_party_poly_uniform_gamma1m1(br_dilithium_third_party_poly *a, const unsigned char *seed,
                                                    size_t seedlen, uint16_t nonce) {
    unsigned int i, ctr, off;
    unsigned int nblocks = (641 + 136) / 136;
    unsigned int buflen = nblocks * 136;
    unsigned char buf[buflen + 4];
    br_shake_context sc;

    br_shake_init(&sc, 256);
    br_shake_inject(&sc, seed, seedlen);
    br_shake_inject(&sc, &nonce, sizeof(nonce));
    br_shake_flip(&sc, 0);
    br_shake_produce(&sc, buf, buflen);

    ctr = rej_gamma1m1(a->coeffs, sizeof(a->coeffs) / sizeof(a->coeffs[0]), buf, buflen);

    while (ctr < sizeof(a->coeffs) / sizeof(a->coeffs[0])) {
        off = buflen % 5;
        for (i = 0; i < off; ++i)
            buf[i] = buf[buflen - off + i];

        buflen = 136 + off;
        br_shake_produce(&sc, buf + off, 1);
        ctr += rej_gamma1m1(a->coeffs + ctr, sizeof(a->coeffs) / sizeof(a->coeffs[0]) - ctr, buf, buflen);
    }
}

/*************************************************
* Name:        polyeta_pack
*
* Description: Bit-pack polynomial with coefficients in [-ETA,ETA].
*              Input coefficients are assumed to lie in [Q-ETA,Q+ETA].
*
* Arguments:   - unsigned char *r: pointer to output byte array with at least
*                                  POLETA_SIZE_PACKED bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void br_dilithium_third_party_polyeta_pack(unsigned char *r, const br_dilithium_third_party_poly *a,
                                           unsigned eta) {
    unsigned int i;
    unsigned char t[8];

    if (2 * eta <= 7) {
        for (i = 0; i < sizeof(a->coeffs) / sizeof(a->coeffs[0]) / 8; ++i) {
            t[0] = BR_DILITHIUM_THIRD_PARTY_Q + eta - a->coeffs[8 * i + 0];
            t[1] = BR_DILITHIUM_THIRD_PARTY_Q + eta - a->coeffs[8 * i + 1];
            t[2] = BR_DILITHIUM_THIRD_PARTY_Q + eta - a->coeffs[8 * i + 2];
            t[3] = BR_DILITHIUM_THIRD_PARTY_Q + eta - a->coeffs[8 * i + 3];
            t[4] = BR_DILITHIUM_THIRD_PARTY_Q + eta - a->coeffs[8 * i + 4];
            t[5] = BR_DILITHIUM_THIRD_PARTY_Q + eta - a->coeffs[8 * i + 5];
            t[6] = BR_DILITHIUM_THIRD_PARTY_Q + eta - a->coeffs[8 * i + 6];
            t[7] = BR_DILITHIUM_THIRD_PARTY_Q + eta - a->coeffs[8 * i + 7];

            r[3 * i + 0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
            r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
            r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
        }
    } else {
        for (i = 0; i < sizeof(a->coeffs) / sizeof(a->coeffs[0]) / 2; ++i) {
            t[0] = BR_DILITHIUM_THIRD_PARTY_Q + eta - a->coeffs[2 * i + 0];
            t[1] = BR_DILITHIUM_THIRD_PARTY_Q + eta - a->coeffs[2 * i + 1];
            r[i] = t[0] | (t[1] << 4);
        }
    }

}

/*************************************************
* Name:        polyeta_unpack
*
* Description: Unpack polynomial with coefficients in [-ETA,ETA].
*              Output coefficients lie in [Q-ETA,Q+ETA].
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const unsigned char *a: byte array with bit-packed polynomial
**************************************************/
void br_dilithium_third_party_polyeta_unpack(br_dilithium_third_party_poly *r, const unsigned char *a,
                                             unsigned eta) {
    unsigned int i;

    if (2 * eta <= 7) {
        for (i = 0; i < sizeof(r->coeffs) / sizeof(r->coeffs[0]) / 8; ++i) {
            r->coeffs[8 * i + 0] = a[3 * i + 0] & 0x07;
            r->coeffs[8 * i + 1] = (a[3 * i + 0] >> 3) & 0x07;
            r->coeffs[8 * i + 2] = ((a[3 * i + 0] >> 6) | (a[3 * i + 1] << 2)) & 0x07;
            r->coeffs[8 * i + 3] = (a[3 * i + 1] >> 1) & 0x07;
            r->coeffs[8 * i + 4] = (a[3 * i + 1] >> 4) & 0x07;
            r->coeffs[8 * i + 5] = ((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 0x07;
            r->coeffs[8 * i + 6] = (a[3 * i + 2] >> 2) & 0x07;
            r->coeffs[8 * i + 7] = (a[3 * i + 2] >> 5) & 0x07;

            r->coeffs[8 * i + 0] = BR_DILITHIUM_THIRD_PARTY_Q + eta - r->coeffs[8 * i + 0];
            r->coeffs[8 * i + 1] = BR_DILITHIUM_THIRD_PARTY_Q + eta - r->coeffs[8 * i + 1];
            r->coeffs[8 * i + 2] = BR_DILITHIUM_THIRD_PARTY_Q + eta - r->coeffs[8 * i + 2];
            r->coeffs[8 * i + 3] = BR_DILITHIUM_THIRD_PARTY_Q + eta - r->coeffs[8 * i + 3];
            r->coeffs[8 * i + 4] = BR_DILITHIUM_THIRD_PARTY_Q + eta - r->coeffs[8 * i + 4];
            r->coeffs[8 * i + 5] = BR_DILITHIUM_THIRD_PARTY_Q + eta - r->coeffs[8 * i + 5];
            r->coeffs[8 * i + 6] = BR_DILITHIUM_THIRD_PARTY_Q + eta - r->coeffs[8 * i + 6];
            r->coeffs[8 * i + 7] = BR_DILITHIUM_THIRD_PARTY_Q + eta - r->coeffs[8 * i + 7];
        }
    } else {
        for (i = 0; i < sizeof(r->coeffs) / sizeof(r->coeffs[0]) / 2; ++i) {
            r->coeffs[2 * i + 0] = a[i] & 0x0F;
            r->coeffs[2 * i + 1] = a[i] >> 4;
            r->coeffs[2 * i + 0] = BR_DILITHIUM_THIRD_PARTY_Q + eta - r->coeffs[2 * i + 0];
            r->coeffs[2 * i + 1] = BR_DILITHIUM_THIRD_PARTY_Q + eta - r->coeffs[2 * i + 1];
        }
    }
}

/*************************************************
* Name:        polyt1_pack
*
* Description: Bit-pack polynomial t1 with coefficients fitting in 9 bits.
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - unsigned char *r: pointer to output byte array with at least
*                                  POLT1_SIZE_PACKED bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void br_dilithium_third_party_polyt1_pack(unsigned char *r, const br_dilithium_third_party_poly *a) {
    unsigned int i;

    for (i = 0; i < sizeof(a->coeffs) / sizeof(a->coeffs[0]) / 8; ++i) {
        r[9 * i + 0] = (a->coeffs[8 * i + 0] >> 0);
        r[9 * i + 1] = (a->coeffs[8 * i + 0] >> 8) | (a->coeffs[8 * i + 1] << 1);
        r[9 * i + 2] = (a->coeffs[8 * i + 1] >> 7) | (a->coeffs[8 * i + 2] << 2);
        r[9 * i + 3] = (a->coeffs[8 * i + 2] >> 6) | (a->coeffs[8 * i + 3] << 3);
        r[9 * i + 4] = (a->coeffs[8 * i + 3] >> 5) | (a->coeffs[8 * i + 4] << 4);
        r[9 * i + 5] = (a->coeffs[8 * i + 4] >> 4) | (a->coeffs[8 * i + 5] << 5);
        r[9 * i + 6] = (a->coeffs[8 * i + 5] >> 3) | (a->coeffs[8 * i + 6] << 6);
        r[9 * i + 7] = (a->coeffs[8 * i + 6] >> 2) | (a->coeffs[8 * i + 7] << 7);
        r[9 * i + 8] = (a->coeffs[8 * i + 7] >> 1);
    }
}

/*************************************************
* Name:        polyt1_unpack
*
* Description: Unpack polynomial t1 with 9-bit coefficients.
*              Output coefficients are standard representatives.
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const unsigned char *a: byte array with bit-packed polynomial
**************************************************/
void br_dilithium_third_party_polyt1_unpack(br_dilithium_third_party_poly *r, const unsigned char *a) {
    unsigned int i;

    for (i = 0; i < sizeof(r->coeffs) / sizeof(r->coeffs[0]) / 8; ++i) {
        r->coeffs[8 * i + 0] = ((a[9 * i + 0] >> 0) | ((uint32_t) a[9 * i + 1] << 8)) & 0x1FF;
        r->coeffs[8 * i + 1] = ((a[9 * i + 1] >> 1) | ((uint32_t) a[9 * i + 2] << 7)) & 0x1FF;
        r->coeffs[8 * i + 2] = ((a[9 * i + 2] >> 2) | ((uint32_t) a[9 * i + 3] << 6)) & 0x1FF;
        r->coeffs[8 * i + 3] = ((a[9 * i + 3] >> 3) | ((uint32_t) a[9 * i + 4] << 5)) & 0x1FF;
        r->coeffs[8 * i + 4] = ((a[9 * i + 4] >> 4) | ((uint32_t) a[9 * i + 5] << 4)) & 0x1FF;
        r->coeffs[8 * i + 5] = ((a[9 * i + 5] >> 5) | ((uint32_t) a[9 * i + 6] << 3)) & 0x1FF;
        r->coeffs[8 * i + 6] = ((a[9 * i + 6] >> 6) | ((uint32_t) a[9 * i + 7] << 2)) & 0x1FF;
        r->coeffs[8 * i + 7] = ((a[9 * i + 7] >> 7) | ((uint32_t) a[9 * i + 8] << 1)) & 0x1FF;
    }
}

/*************************************************
* Name:        polyt0_pack
*
* Description: Bit-pack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
*              Input coefficients are assumed to lie in ]Q-2^{D-1}, Q+2^{D-1}].
*
* Arguments:   - unsigned char *r: pointer to output byte array with at least
*                                  POLT0_SIZE_PACKED bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void br_dilithium_third_party_polyt0_pack(unsigned char *r, const br_dilithium_third_party_poly *a) {
    unsigned int i;
    uint32_t t[4];

    for (i = 0; i < sizeof(a->coeffs) / sizeof(a->coeffs[0]) / 4; ++i) {
        t[0] = BR_DILITHIUM_THIRD_PARTY_Q + (1U << (BR_DILITHIUM_THIRD_PARTY_D - 1)) - a->coeffs[4 * i + 0];
        t[1] = BR_DILITHIUM_THIRD_PARTY_Q + (1U << (BR_DILITHIUM_THIRD_PARTY_D - 1)) - a->coeffs[4 * i + 1];
        t[2] = BR_DILITHIUM_THIRD_PARTY_Q + (1U << (BR_DILITHIUM_THIRD_PARTY_D - 1)) - a->coeffs[4 * i + 2];
        t[3] = BR_DILITHIUM_THIRD_PARTY_Q + (1U << (BR_DILITHIUM_THIRD_PARTY_D - 1)) - a->coeffs[4 * i + 3];

        r[7 * i + 0] = t[0];
        r[7 * i + 1] = t[0] >> 8;
        r[7 * i + 1] |= t[1] << 6;
        r[7 * i + 2] = t[1] >> 2;
        r[7 * i + 3] = t[1] >> 10;
        r[7 * i + 3] |= t[2] << 4;
        r[7 * i + 4] = t[2] >> 4;
        r[7 * i + 5] = t[2] >> 12;
        r[7 * i + 5] |= t[3] << 2;
        r[7 * i + 6] = t[3] >> 6;
    }
}

/*************************************************
* Name:        polyt0_unpack
*
* Description: Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
*              Output coefficients lie in ]Q-2^{D-1},Q+2^{D-1}].
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const unsigned char *a: byte array with bit-packed polynomial
**************************************************/
void br_dilithium_third_party_polyt0_unpack(br_dilithium_third_party_poly *r, const unsigned char *a) {
    unsigned int i;

    for (i = 0; i < sizeof(r->coeffs) / sizeof(r->coeffs[0]) / 4; ++i) {
        r->coeffs[4 * i + 0] = a[7 * i + 0];
        r->coeffs[4 * i + 0] |= (uint32_t)(a[7 * i + 1] & 0x3F) << 8;

        r->coeffs[4 * i + 1] = a[7 * i + 1] >> 6;
        r->coeffs[4 * i + 1] |= (uint32_t) a[7 * i + 2] << 2;
        r->coeffs[4 * i + 1] |= (uint32_t)(a[7 * i + 3] & 0x0F) << 10;

        r->coeffs[4 * i + 2] = a[7 * i + 3] >> 4;
        r->coeffs[4 * i + 2] |= (uint32_t) a[7 * i + 4] << 4;
        r->coeffs[4 * i + 2] |= (uint32_t)(a[7 * i + 5] & 0x03) << 12;

        r->coeffs[4 * i + 3] = a[7 * i + 5] >> 2;
        r->coeffs[4 * i + 3] |= (uint32_t) a[7 * i + 6] << 6;

        r->coeffs[4 * i + 0] =
                BR_DILITHIUM_THIRD_PARTY_Q + (1U << (BR_DILITHIUM_THIRD_PARTY_D - 1)) - r->coeffs[4 * i + 0];
        r->coeffs[4 * i + 1] =
                BR_DILITHIUM_THIRD_PARTY_Q + (1U << (BR_DILITHIUM_THIRD_PARTY_D - 1)) - r->coeffs[4 * i + 1];
        r->coeffs[4 * i + 2] =
                BR_DILITHIUM_THIRD_PARTY_Q + (1U << (BR_DILITHIUM_THIRD_PARTY_D - 1)) - r->coeffs[4 * i + 2];
        r->coeffs[4 * i + 3] =
                BR_DILITHIUM_THIRD_PARTY_Q + (1U << (BR_DILITHIUM_THIRD_PARTY_D - 1)) - r->coeffs[4 * i + 3];
    }
}

/*************************************************
* Name:        polyz_pack
*
* Description: Bit-pack polynomial z with coefficients
*              in [-(GAMMA1 - 1), GAMMA1 - 1].
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - unsigned char *r: pointer to output byte array with at least
*                                  POLZ_SIZE_PACKED bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void br_dilithium_third_party_polyz_pack(unsigned char *r, const br_dilithium_third_party_poly *a) {
    unsigned int i;
    uint32_t t[2];

    for (i = 0; i < sizeof(a->coeffs) / sizeof(a->coeffs[0]) / 2; ++i) {
        /* Map to {0,...,2*GAMMA1 - 2} */
        t[0] = BR_DILITHIUM_THIRD_PARTY_GAMMA1 - 1 - a->coeffs[2 * i + 0];
        t[0] += ((int32_t) t[0] >> 31) & BR_DILITHIUM_THIRD_PARTY_Q;
        t[1] = BR_DILITHIUM_THIRD_PARTY_GAMMA1 - 1 - a->coeffs[2 * i + 1];
        t[1] += ((int32_t) t[1] >> 31) & BR_DILITHIUM_THIRD_PARTY_Q;

        r[5 * i + 0] = t[0];
        r[5 * i + 1] = t[0] >> 8;
        r[5 * i + 2] = t[0] >> 16;
        r[5 * i + 2] |= t[1] << 4;
        r[5 * i + 3] = t[1] >> 4;
        r[5 * i + 4] = t[1] >> 12;
    }
}

/*************************************************
* Name:        polyz_unpack
*
* Description: Unpack polynomial z with coefficients
*              in [-(GAMMA1 - 1), GAMMA1 - 1].
*              Output coefficients are standard representatives.
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const unsigned char *a: byte array with bit-packed polynomial
**************************************************/
void br_dilithium_third_party_polyz_unpack(br_dilithium_third_party_poly *r, const unsigned char *a) {
    unsigned int i;

    for (i = 0; i < sizeof(r->coeffs) / sizeof(r->coeffs[0]) / 2; ++i) {
        r->coeffs[2 * i + 0] = a[5 * i + 0];
        r->coeffs[2 * i + 0] |= (uint32_t) a[5 * i + 1] << 8;
        r->coeffs[2 * i + 0] |= (uint32_t)(a[5 * i + 2] & 0x0F) << 16;

        r->coeffs[2 * i + 1] = a[5 * i + 2] >> 4;
        r->coeffs[2 * i + 1] |= (uint32_t) a[5 * i + 3] << 4;
        r->coeffs[2 * i + 1] |= (uint32_t) a[5 * i + 4] << 12;

        r->coeffs[2 * i + 0] = BR_DILITHIUM_THIRD_PARTY_GAMMA1 - 1 - r->coeffs[2 * i + 0];
        r->coeffs[2 * i + 0] += ((int32_t) r->coeffs[2 * i + 0] >> 31) & BR_DILITHIUM_THIRD_PARTY_Q;
        r->coeffs[2 * i + 1] = BR_DILITHIUM_THIRD_PARTY_GAMMA1 - 1 - r->coeffs[2 * i + 1];
        r->coeffs[2 * i + 1] += ((int32_t) r->coeffs[2 * i + 1] >> 31) & BR_DILITHIUM_THIRD_PARTY_Q;
    }
}

/*************************************************
* Name:        polyw1_pack
*
* Description: Bit-pack polynomial w1 with coefficients in [0, 15].
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - unsigned char *r: pointer to output byte array with at least
*                                  POLW1_SIZE_PACKED bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void br_dilithium_third_party_polyw1_pack(unsigned char *r, const br_dilithium_third_party_poly *a) {
    unsigned int i;

    for (i = 0; i < sizeof(a->coeffs) / sizeof(a->coeffs[0]) / 2; ++i)
        r[i] = a->coeffs[2 * i + 0] | (a->coeffs[2 * i + 1] << 4);
}
