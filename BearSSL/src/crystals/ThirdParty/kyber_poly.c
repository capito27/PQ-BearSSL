#include <stdint.h>
#include "inc/kyber_poly.h"
#include "inc/kyber_ntt.h"
#include "inc/kyber_reduce.h"
#include "inc/kyber_cbd.h"
#include "inner.h"

/*************************************************
* Name:        poly_compress
*
* Description: Compression and subsequent serialization of a polynomial
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (of length KYBER_POLYCOMPRESSEDBYTES)
*              - poly *a:    pointer to input polynomial
**************************************************/
void br_kyber_third_party_poly_compress(uint8_t *r, unsigned polynbr, br_kyber_third_party_poly *a) {
    unsigned int i, j;
    uint8_t t[8];

    br_kyber_third_party_poly_csubq(a);
    if (polynbr == 2) {
        for (i = 0; i < sizeof(a->coeffs) / sizeof(a->coeffs[0]) / 8; i++) {
            for (j = 0; j < 8; j++)
                t[j] = ((((uint16_t) a->coeffs[8 * i + j] << 3) + BR_KYBER_THIRD_PARTY_Q / 2) /
                        BR_KYBER_THIRD_PARTY_Q) & 7;

            r[0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
            r[1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
            r[2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
            r += 3;
        }
    } else if (polynbr == 3) {
        for (i = 0; i < sizeof(a->coeffs) / sizeof(a->coeffs[0]) / 8; i++) {
            for (j = 0; j < 8; j++)
                t[j] = ((((uint16_t) a->coeffs[8 * i + j] << 4) + BR_KYBER_THIRD_PARTY_Q / 2) /
                        BR_KYBER_THIRD_PARTY_Q) & 15;

            r[0] = t[0] | (t[1] << 4);
            r[1] = t[2] | (t[3] << 4);
            r[2] = t[4] | (t[5] << 4);
            r[3] = t[6] | (t[7] << 4);
            r += 4;
        }
    } else if (polynbr == 4) {
        for (i = 0; i < sizeof(a->coeffs) / sizeof(a->coeffs[0]) / 8; i++) {
            for (j = 0; j < 8; j++)
                t[j] = ((((uint32_t) a->coeffs[8 * i + j] << 5) + BR_KYBER_THIRD_PARTY_Q / 2) /
                        BR_KYBER_THIRD_PARTY_Q) & 31;

            r[0] = (t[0] >> 0) | (t[1] << 5);
            r[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
            r[2] = (t[3] >> 1) | (t[4] << 4);
            r[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
            r[4] = (t[6] >> 2) | (t[7] << 3);
            r += 5;
        }
    }
}

/*************************************************
* Name:        poly_decompress
*
* Description: De-serialization and subsequent decompression of a polynomial;
*              approximate inverse of poly_compress
*
* Arguments:   - poly *r:          pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array
*                                  (of length KYBER_POLYCOMPRESSEDBYTES bytes)
**************************************************/
void br_kyber_third_party_poly_decompress(br_kyber_third_party_poly *r, const uint8_t *a, unsigned polynbr) {
    unsigned int i;

    if (polynbr == 2) {
        unsigned int j;
        uint8_t t[8];
        for (i = 0; i < sizeof(r->coeffs) / sizeof(r->coeffs[0]) / 8; i++) {
            t[0] = (a[0] >> 0);
            t[1] = (a[0] >> 3);
            t[2] = (a[0] >> 6) | (a[1] << 2);
            t[3] = (a[1] >> 1);
            t[4] = (a[1] >> 4);
            t[5] = (a[1] >> 7) | (a[2] << 1);
            t[6] = (a[2] >> 2);
            t[7] = (a[2] >> 5);
            a += 3;

            for (j = 0; j < 8; j++)
                r->coeffs[8 * i + j] = ((uint16_t)(t[j] & 7) * BR_KYBER_THIRD_PARTY_Q + 4) >> 3;
        }
    } else if (polynbr == 3) {
        for (i = 0; i < sizeof(r->coeffs) / sizeof(r->coeffs[0]) / 2; i++) {
            r->coeffs[2 * i + 0] = (((uint16_t)(a[0] & 15) * BR_KYBER_THIRD_PARTY_Q) + 8) >> 4;
            r->coeffs[2 * i + 1] = (((uint16_t)(a[0] >> 4) * BR_KYBER_THIRD_PARTY_Q) + 8) >> 4;
            a += 1;
        }
    } else if (polynbr == 4) {
        unsigned int j;
        uint8_t t[8];
        for (i = 0; i < sizeof(r->coeffs) / sizeof(r->coeffs[0]) / 8; i++) {
            t[0] = (a[0] >> 0);
            t[1] = (a[0] >> 5) | (a[1] << 3);
            t[2] = (a[1] >> 2);
            t[3] = (a[1] >> 7) | (a[2] << 1);
            t[4] = (a[2] >> 4) | (a[3] << 4);
            t[5] = (a[3] >> 1);
            t[6] = (a[3] >> 6) | (a[4] << 2);
            t[7] = (a[4] >> 3);
            a += 5;

            for (j = 0; j < 8; j++)
                r->coeffs[8 * i + j] = ((uint32_t)(t[j] & 31) * BR_KYBER_THIRD_PARTY_Q + 16) >> 5;
        }
    }
}

/*************************************************
* Name:        poly_tobytes
*
* Description: Serialization of a polynomial
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYBYTES bytes)
*              - poly *a:    pointer to input polynomial
**************************************************/
void br_kyber_third_party_poly_tobytes(uint8_t *r, br_kyber_third_party_poly *a) {
    unsigned int i;
    uint16_t t0, t1;

    br_kyber_third_party_poly_csubq(a);

    for (i = 0; i < sizeof(a->coeffs) / sizeof(a->coeffs[0]) / 2; i++) {
        t0 = a->coeffs[2 * i];
        t1 = a->coeffs[2 * i + 1];
        r[3 * i + 0] = (t0 >> 0);
        r[3 * i + 1] = (t0 >> 8) | (t1 << 4);
        r[3 * i + 2] = (t1 >> 4);
    }
}

/*************************************************
* Name:        poly_frombytes
*
* Description: De-serialization of a polynomial;
*              inverse of poly_tobytes
*
* Arguments:   - poly *r:          pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array
*                                  (of KYBER_POLYBYTES bytes)
**************************************************/
void br_kyber_third_party_poly_frombytes(br_kyber_third_party_poly *r, const uint8_t *a) {
    unsigned int i;
    for (i = 0; i < sizeof(r->coeffs) / sizeof(r->coeffs[0]) / 2; i++) {
        r->coeffs[2 * i] = ((a[3 * i + 0] >> 0) | ((uint16_t) a[3 * i + 1] << 8)) & 0xFFF;
        r->coeffs[2 * i + 1] = ((a[3 * i + 1] >> 4) | ((uint16_t) a[3 * i + 2] << 4)) & 0xFFF;
    }
}

/*************************************************
* Name:        poly_tomsg
*
* Description: Convert polynomial to 32-byte message
*
* Arguments:   - uint8_t *msg: pointer to output message
*              - poly *a:      pointer to input polynomial
**************************************************/
void br_kyber_third_party_poly_tomsg(uint8_t *msg, br_kyber_third_party_poly *a) {
    unsigned int i, j;
    uint16_t t;

    br_kyber_third_party_poly_csubq(a);

    for (i = 0; i < sizeof(a->coeffs) / sizeof(a->coeffs[0]) / 8; i++) {
        msg[i] = 0;
        for (j = 0; j < 8; j++) {
            t = ((((uint16_t) a->coeffs[8 * i + j] << 1) + BR_KYBER_THIRD_PARTY_Q / 2) / BR_KYBER_THIRD_PARTY_Q) & 1;
            msg[i] |= t << j;
        }
    }
}

/*************************************************
* Name:        poly_frommsg
*
* Description: Convert 32-byte message to polynomial
*
* Arguments:   - poly *r:            pointer to output polynomial
*              - const uint8_t *msg: pointer to input message
**************************************************/
void br_kyber_third_party_poly_frommsg(br_kyber_third_party_poly *r, const uint8_t *msg) {
    unsigned int i, j;
    int16_t mask;


    for (i = 0; i < sizeof(r->coeffs) / sizeof(r->coeffs[0]) / 8; i++) {
        for (j = 0; j < 8; j++) {
            mask = -(int16_t)((msg[i] >> j) & 1);
            r->coeffs[8 * i + j] = mask & ((BR_KYBER_THIRD_PARTY_Q + 1) / 2);
        }
    }

}

/*************************************************
* Name:        poly_ntt
*
* Description: Computes negacyclic number-theoretic transform (NTT) of
*              a polynomial in place;
*              inputs assumed to be in normal order, output in bitreversed order
*
* Arguments:   - uint16_t *r: pointer to in/output polynomial
**************************************************/
void br_kyber_third_party_poly_ntt(br_kyber_third_party_poly *r) {
    br_kyber_third_party_ntt(r->coeffs, sizeof(r->coeffs) / sizeof(r->coeffs[0]));
    br_kyber_third_party_poly_reduce(r);
}

/*************************************************
* Name:        poly_invntt_tomont
*
* Description: Computes inverse of negacyclic number-theoretic transform (NTT)
*              of a polynomial in place;
*              inputs assumed to be in bitreversed order, output in normal order
*
* Arguments:   - uint16_t *a: pointer to in/output polynomial
**************************************************/
void br_kyber_third_party_poly_invntt_tomont(br_kyber_third_party_poly *r) {
    br_kyber_third_party_invntt(r->coeffs, sizeof(r->coeffs) / sizeof(r->coeffs[0]));
}

/*************************************************
* Name:        poly_basemul_montgomery
*
* Description: Multiplication of two polynomials in NTT domain
*
* Arguments:   - poly *r:       pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void br_kyber_third_party_poly_basemul_montgomery(br_kyber_third_party_poly *r, const br_kyber_third_party_poly *a,
                                                  const br_kyber_third_party_poly *b) {
    unsigned int i;
    for (i = 0; i < sizeof(r->coeffs) / sizeof(r->coeffs[0]) / 4; i++) {
        br_kyber_third_party_basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i],
                                     br_kyber_third_party_zetas[64 + i]);
        br_kyber_third_party_basemul(&r->coeffs[4 * i + 2], &a->coeffs[4 * i + 2], &b->coeffs[4 * i + 2],
                                     -br_kyber_third_party_zetas[64 + i]);
    }
}

/*************************************************
* Name:        poly_tomont
*
* Description: Inplace conversion of all coefficients of a polynomial
*              from normal domain to Montgomery domain
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void br_kyber_third_party_poly_tomont(br_kyber_third_party_poly *r) {
    unsigned int i;
    const int16_t f = (1ULL << 32) % BR_KYBER_THIRD_PARTY_Q;
    for (i = 0; i < sizeof(r->coeffs) / sizeof(r->coeffs[0]); i++)
        r->coeffs[i] = br_kyber_third_party_montgomery_reduce((int32_t) r->coeffs[i] * f);
}

/*************************************************
* Name:        poly_reduce
*
* Description: Applies Barrett reduction to all coefficients of a polynomial
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void br_kyber_third_party_poly_reduce(br_kyber_third_party_poly *r) {
    unsigned int i;
    for (i = 0; i < sizeof(r->coeffs) / sizeof(r->coeffs[0]); i++)
        r->coeffs[i] = br_kyber_third_party_barrett_reduce(r->coeffs[i]);
}

/*************************************************
* Name:        poly_csubq
*
* Description: Applies conditional subtraction of q to each coefficient
*              of a polynomial. For details of conditional subtraction
*              of q see comments in reduce.c
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void br_kyber_third_party_poly_csubq(br_kyber_third_party_poly *r) {
    unsigned int i;
    for (i = 0; i < sizeof(r->coeffs) / sizeof(r->coeffs[0]); i++)
        r->coeffs[i] = br_kyber_third_party_csubq(r->coeffs[i]);
}

/*************************************************
* Name:        poly_add
*
* Description: Add two polynomials
*
* Arguments: - poly *r:       pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void br_kyber_third_party_poly_add(br_kyber_third_party_poly *r, const br_kyber_third_party_poly *a,
                                   const br_kyber_third_party_poly *b) {
    unsigned int i;
    for (i = 0; i < sizeof(r->coeffs) / sizeof(r->coeffs[0]); i++)
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

/*************************************************
* Name:        poly_sub
*
* Description: Subtract two polynomials
*
* Arguments: - poly *r:       pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void br_kyber_third_party_poly_sub(br_kyber_third_party_poly *r, const br_kyber_third_party_poly *a,
                                   const br_kyber_third_party_poly *b) {
    unsigned int i;
    for (i = 0; i < sizeof(r->coeffs) / sizeof(r->coeffs[0]); i++)
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}
