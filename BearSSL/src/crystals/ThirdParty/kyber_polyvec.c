#include <stdint.h>
#include "inc/kyber_poly.h"
#include "inc/kyber_polyvec.h"
#include "inc/kyber_reduce.h"

/*************************************************
* Name:        polyvec_compress
*
* Description: Compress and serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYVECCOMPRESSEDBYTES)
*              - polyvec *a: pointer to input vector of polynomials
**************************************************/

void br_kyber_third_party_polyvec_compress(uint8_t *r, unsigned polynbr, br_kyber_third_party_polyvec *a) {
    unsigned int i, j, k;

    br_kyber_third_party_polyvec_csubq(a);
    if (polynbr == 4) {
        uint16_t t[8];
        for (i = 0; i < a->veclen; i++) {
            for (j = 0; j < sizeof(a->vec[i].coeffs) / sizeof(a->vec[i].coeffs[0]) / 8; j++) {
                for (k = 0; k < 8; k++)
                    t[k] = ((((uint32_t) a->vec[i].coeffs[8 * j + k] << 11) + BR_KYBER_THIRD_PARTY_Q / 2)
                            / BR_KYBER_THIRD_PARTY_Q) & 0x7ff;

                r[0] = (t[0] >> 0);
                r[1] = (t[0] >> 8) | (t[1] << 3);
                r[2] = (t[1] >> 5) | (t[2] << 6);
                r[3] = (t[2] >> 2);
                r[4] = (t[2] >> 10) | (t[3] << 1);
                r[5] = (t[3] >> 7) | (t[4] << 4);
                r[6] = (t[4] >> 4) | (t[5] << 7);
                r[7] = (t[5] >> 1);
                r[8] = (t[5] >> 9) | (t[6] << 2);
                r[9] = (t[6] >> 6) | (t[7] << 5);
                r[10] = (t[7] >> 3);
                r += 11;
            }
        }
    } else {
        uint16_t t[4];
        for (i = 0; i < a->veclen; i++) {
            for (j = 0; j < sizeof(a->vec[i].coeffs) / sizeof(a->vec[i].coeffs[0]) / 4; j++) {
                for (k = 0; k < 4; k++)
                    t[k] = ((((uint32_t) a->vec[i].coeffs[4 * j + k] << 10) + BR_KYBER_THIRD_PARTY_Q / 2)
                            / BR_KYBER_THIRD_PARTY_Q) & 0x3ff;

                r[0] = (t[0] >> 0);
                r[1] = (t[0] >> 8) | (t[1] << 2);
                r[2] = (t[1] >> 6) | (t[2] << 4);
                r[3] = (t[2] >> 4) | (t[3] << 6);
                r[4] = (t[3] >> 2);
                r += 5;
            }
        }
    }
}

/*************************************************
* Name:        polyvec_decompress
*
* Description: De-serialize and decompress vector of polynomials;
*              approximate inverse of polyvec_compress
*
* Arguments:   - polyvec *r:       pointer to output vector of polynomials
*              - const uint8_t *a: pointer to input byte array
*                                  (of length KYBER_POLYVECCOMPRESSEDBYTES)
**************************************************/
void br_kyber_third_party_polyvec_decompress(br_kyber_third_party_polyvec *r, const uint8_t *a, unsigned polynbr) {
    unsigned int i, j, k;

    if (polynbr == 4) {
        uint16_t t[8];
        for (i = 0; i < r->veclen; i++) {
            for (j = 0; j < sizeof(r->vec[i].coeffs) / sizeof(r->vec[i].coeffs[0]) / 8; j++) {
                t[0] = (a[0] >> 0) | ((uint16_t) a[1] << 8);
                t[1] = (a[1] >> 3) | ((uint16_t) a[2] << 5);
                t[2] = (a[2] >> 6) | ((uint16_t) a[3] << 2) | ((uint16_t) a[4] << 10);
                t[3] = (a[4] >> 1) | ((uint16_t) a[5] << 7);
                t[4] = (a[5] >> 4) | ((uint16_t) a[6] << 4);
                t[5] = (a[6] >> 7) | ((uint16_t) a[7] << 1) | ((uint16_t) a[8] << 9);
                t[6] = (a[8] >> 2) | ((uint16_t) a[9] << 6);
                t[7] = (a[9] >> 5) | ((uint16_t) a[10] << 3);
                a += 11;

                for (k = 0; k < 8; k++)
                    r->vec[i].coeffs[8 * j + k] = ((uint32_t)(t[k] & 0x7FF) * BR_KYBER_THIRD_PARTY_Q + 1024) >> 11;
            }
        }
    } else {
        uint16_t t[4];
        for (i = 0; i < r->veclen; i++) {
            for (j = 0; j < sizeof(r->vec[i].coeffs) / sizeof(r->vec[i].coeffs[0]) / 4; j++) {
                t[0] = (a[0] >> 0) | ((uint16_t) a[1] << 8);
                t[1] = (a[1] >> 2) | ((uint16_t) a[2] << 6);
                t[2] = (a[2] >> 4) | ((uint16_t) a[3] << 4);
                t[3] = (a[3] >> 6) | ((uint16_t) a[4] << 2);
                a += 5;

                for (k = 0; k < 4; k++)
                    r->vec[i].coeffs[4 * j + k] = ((uint32_t)(t[k] & 0x3FF) * BR_KYBER_THIRD_PARTY_Q + 512) >> 10;
            }
        }
    }
}

/*************************************************
* Name:        polyvec_tobytes
*
* Description: Serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYVECBYTES)
*              - polyvec *a: pointer to input vector of polynomials
**************************************************/
void br_kyber_third_party_polyvec_tobytes(uint8_t *r, br_kyber_third_party_polyvec *a) {
    unsigned int i;
    for (i = 0; i < a->veclen; i++)
        br_kyber_third_party_poly_tobytes(r + i * 384, &a->vec[i]);
}

/*************************************************
* Name:        polyvec_frombytes
*
* Description: De-serialize vector of polynomials;
*              inverse of polyvec_tobytes
*
* Arguments:   - uint8_t *r:       pointer to output byte array
*              - const polyvec *a: pointer to input vector of polynomials
*                                  (of length KYBER_POLYVECBYTES)
**************************************************/
void br_kyber_third_party_polyvec_frombytes(br_kyber_third_party_polyvec *r, const uint8_t *a) {
    unsigned int i;
    for (i = 0; i < r->veclen; i++)
        br_kyber_third_party_poly_frombytes(&r->vec[i], a + i * 384);
}

/*************************************************
* Name:        polyvec_ntt
*
* Description: Apply forward NTT to all elements of a vector of polynomials
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void br_kyber_third_party_polyvec_ntt(br_kyber_third_party_polyvec *r) {
    unsigned int i;
    for (i = 0; i < r->veclen; i++)
        br_kyber_third_party_poly_ntt(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_invntt_tomont
*
* Description: Apply inverse NTT to all elements of a vector of polynomials
*              and multiply by Montgomery factor 2^16
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void br_kyber_third_party_polyvec_invntt_tomont(br_kyber_third_party_polyvec *r) {
    unsigned int i;
    for (i = 0; i < r->veclen; i++)
        br_kyber_third_party_poly_invntt_tomont(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_pointwise_acc_montgomery
*
* Description: Pointwise multiply elements of a and b, accumulate into r,
*              and multiply by 2^-16.
*
* Arguments: - poly *r:          pointer to output polynomial
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void br_kyber_third_party_polyvec_pointwise_acc_montgomery(br_kyber_third_party_poly *r,
                                                           const br_kyber_third_party_polyvec *a,
                                                           const br_kyber_third_party_polyvec *b) {
    unsigned int i;
    br_kyber_third_party_poly t;

    br_kyber_third_party_poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
    for (i = 1; i < a->veclen; i++) {
        br_kyber_third_party_poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
        br_kyber_third_party_poly_add(r, r, &t);
    }

    br_kyber_third_party_poly_reduce(r);
}

/*************************************************
* Name:        polyvec_reduce
*
* Description: Applies Barrett reduction to each coefficient
*              of each element of a vector of polynomials
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void br_kyber_third_party_polyvec_reduce(br_kyber_third_party_polyvec *r) {
    unsigned int i;
    for (i = 0; i < r->veclen; i++)
        br_kyber_third_party_poly_reduce(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_csubq
*
* Description: Applies conditional subtraction of q to each coefficient
*              of each element of a vector of polynomials
*              for details of conditional subtraction of q see comments in
*              reduce.c
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void br_kyber_third_party_polyvec_csubq(br_kyber_third_party_polyvec *r) {
    unsigned int i;
    for (i = 0; i < r->veclen; i++)
        br_kyber_third_party_poly_csubq(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_add
*
* Description: Add vectors of polynomials
*
* Arguments: - polyvec *r:       pointer to output vector of polynomials
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void br_kyber_third_party_polyvec_add(br_kyber_third_party_polyvec *r, const br_kyber_third_party_polyvec *a,
                                      const br_kyber_third_party_polyvec *b) {
    unsigned int i;
    for (i = 0; i < r->veclen; i++)
        br_kyber_third_party_poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}
