#include "inner.h"
#include "inc/dilithium_poly.h"
#include "inc/dilithium_polyvec.h"
#include "inc/dilithium_packing.h"
#include "inc/dilithium_reduce.h"
#include <assert.h>


/*************************************************
* Name:        pack_pk
*
* Description: Bit-pack public key pk = (rho, t1).
*
* Arguments:   - unsigned char pk[]: output byte array
*              - const polyveck *t1: pointer to vector t1
**************************************************/
void br_dilithium_third_party_pack_pk(br_dilithium_public_key *pk,
                                      const br_dilithium_third_party_polyvec *t1) {
    unsigned int i;

    for (i = 0; i < t1->polylen; ++i)
        br_dilithium_third_party_polyt1_pack(pk->t1 + i * 288, &t1->vec[i]);
    pk->t1len = t1->polylen * 288;
}

/*************************************************
* Name:        unpack_pk
*
* Description: Unpack public key pk = (rho, t1).
*
* Arguments:   - const polyveck *t1: pointer to output vector t1
*              - unsigned char pk[]: byte array containing bit-packed pk
**************************************************/
void br_dilithium_third_party_unpack_pk(br_dilithium_third_party_polyvec *t1,
                                        const br_dilithium_public_key *pk) {
    unsigned int i;

    for (i = 0; i < pk->mode + 2u; ++i)
        br_dilithium_third_party_polyt1_unpack(&t1->vec[i], pk->t1 + i * 288);
}

#define polyeta_packed(mode) ((mode) <= 3 ? 128 : 96)

/*************************************************
* Name:        pack_sk
*
* Description: Bit-pack secret key sk = (s1, s2, t0).
*
* Arguments:   - unsigned char sk[]: output byte array
*              - const polyvecl *s1: pointer to vector s1
*              - const polyveck *s2: pointer to vector s2
*              - const polyveck *t0: pointer to vector t0
*
* NB : At least one argument to pack MUST be defined
**************************************************/
void br_dilithium_third_party_pack_sk(br_dilithium_private_key *sk,
                                      const br_dilithium_third_party_polyvec *s1,
                                      const br_dilithium_third_party_polyvec *s2,
                                      const br_dilithium_third_party_polyvec *t0, unsigned mode) {
    unsigned int i, eta;
    eta = mode <= 3 ? 8 - mode : 3;

    if (s1) {
        for (i = 0; i < s1->polylen; ++i)
            br_dilithium_third_party_polyeta_pack(sk->s1 + i * polyeta_packed(mode), &s1->vec[i], eta);
        sk->s1len = s1->polylen * polyeta_packed(mode);
    }
    if (s2) {
        for (i = 0; i < s2->polylen; ++i)
            br_dilithium_third_party_polyeta_pack(sk->s2 + i * polyeta_packed(mode),&s2->vec[i], eta);
        sk->s2len = s2->polylen * polyeta_packed(mode);
    }
    if (t0) {
        for (i = 0; i < t0->polylen; ++i)
            br_dilithium_third_party_polyt0_pack(sk->t0 + i * 448, &t0->vec[i]);
        sk->t0len = t0->polylen * 448;
    }

}

/*************************************************
* Name:        unpack_sk
*
* Description: Unpack secret key sk = (rho, key, tr, s1, s2, t0).
*
* Arguments:   - const polyvecl *s1: pointer to output vector s1
*              - const polyveck *s2: pointer to output vector s2
*              - const polyveck *r0: pointer to output vector t0
*              - unsigned char sk[]: byte array containing bit-packed sk
 *
* NB : At least one argument to pack MUST be defined
**************************************************/

void br_dilithium_third_party_unpack_sk(br_dilithium_third_party_polyvec *s1,
                                        br_dilithium_third_party_polyvec *s2,
                                        br_dilithium_third_party_polyvec *t0,
                                        const br_dilithium_private_key *sk) {
    unsigned int i;
    unsigned int eta;
    eta = sk->mode <= 3 ? 8 - sk->mode : 3;
    if (s1) {
        for (i = 0; i < sk->mode + 1u; ++i)
            br_dilithium_third_party_polyeta_unpack(&s1->vec[i], sk->s1 + i * polyeta_packed(sk->mode), eta);
    }
    if (s2) {
        for (i = 0; i < sk->mode + 2u; ++i)
            br_dilithium_third_party_polyeta_unpack(&s2->vec[i], sk->s2 + i * polyeta_packed(sk->mode), eta);
    }
    if (t0) {
        for (i = 0; i < sk->mode + 2u; ++i)
            br_dilithium_third_party_polyt0_unpack(&t0->vec[i], sk->t0 + i * 448);
    }
}

/*************************************************
* Name:        pack_sig
*
* Description: Bit-pack signature sig = (z, h, c).
*
* Arguments:   - unsigned char sig[]: output byte array
*              - const polyvecl *z: pointer to vector z
*              - const polyveck *h: pointer to hint vector h
*              - const poly *c: pointer to challenge polynomial
*
* NB : At least one argument to pack MUST be defined
**************************************************/
void br_dilithium_third_party_pack_sig(unsigned char *sig,
                                       const br_dilithium_third_party_polyvec *z,
                                       const br_dilithium_third_party_polyvec *h,
                                       const br_dilithium_third_party_poly *c, unsigned mode) {
    unsigned int i, j, k;
    uint64_t signs, mask;
    unsigned int omega;
    omega = (mode <= 3 ? 48 + 16 * mode : 120);


    if (z) {
        for (i = 0; i < z->polylen; ++i)
            br_dilithium_third_party_polyz_pack(sig + i * 640, &z->vec[i]);
    }
    sig += (mode + 1) * 640;

    /* Encode h */
    if (h) {
        k = 0;
        for (i = 0; i < h->polylen; ++i) {
            for (j = 0; j < sizeof(h->vec[i].coeffs) / sizeof(h->vec[i].coeffs[0]); ++j)
                if (h->vec[i].coeffs[j] != 0)
                    sig[k++] = j;

            sig[omega + i] = k;
        }
        while (k < omega) sig[k++] = 0;
    }
    sig += omega + mode + 2;

    /* Encode c */
    if (c) {
        signs = 0;
        mask = 1;
        for (i = 0; i <  sizeof(c->coeffs) / sizeof(c->coeffs[0]) / 8; ++i) {
            sig[i] = 0;
            for (j = 0; j < 8; ++j) {
                if (c->coeffs[8 * i + j] != 0) {
                    sig[i] |= (1U << j);
                    if (c->coeffs[8 * i + j] == (BR_DILITHIUM_THIRD_PARTY_Q - 1)) signs |= mask;
                    mask <<= 1;
                }
            }
        }
        sig += sizeof(c->coeffs) / sizeof(c->coeffs[0]) / 8;
        for (i = 0; i < 8; ++i)
            sig[i] = signs >> 8 * i;
    }
}

/*************************************************
* Name:        unpack_sig
*
* Description: Unpack signature sig = (z, h, c).
*
* Arguments:   - polyvecl *z: pointer to output vector z
*              - polyveck *h: pointer to output hint vector h
*              - poly *c: pointer to output challenge polynomial
*              - const unsigned char sig[]: byte array containing
*                bit-packed signature
*
* Returns 1 in case of malformed signature; otherwise 0.
**************************************************/
int br_dilithium_third_party_unpack_sig(br_dilithium_third_party_polyvec *z,
                                        br_dilithium_third_party_polyvec *h,
                                        br_dilithium_third_party_poly *c,
                                        const unsigned char *sig, unsigned mode) {
    unsigned int i, j, k;
    uint64_t signs;
    unsigned omega;
    omega = (mode <= 3 ? 48 + 16 * mode : 120);

    for (i = 0; i < mode + 1; ++i)
        br_dilithium_third_party_polyz_unpack(&z->vec[i], sig + i * 640);
    sig += (mode + 1) * 640;

    /* Decode h */
    k = 0;
    for (i = 0; i < mode + 2; ++i) {
        for (j = 0; j < sizeof(h->vec[i].coeffs) / sizeof(h->vec[i].coeffs[0]); ++j)
            h->vec[i].coeffs[j] = 0;

        if (sig[omega + i] < k || sig[omega + i] > omega)
            return 1;

        for (j = k; j < sig[omega + i]; ++j) {
            /* Coefficients are ordered for strong unforgeability */
            if (j > k && sig[j] <= sig[j - 1]) return 1;
            h->vec[i].coeffs[sig[j]] = 1;
        }

        k = sig[omega + i];
    }

    /* Extra indices are zero for strong unforgeability */
    for (j = k; j < omega; ++j)
        if (sig[j])
            return 1;

    sig += omega + mode + 2;

    /* Decode c */
    for (i = 0; i < sizeof(c->coeffs) / sizeof(c->coeffs[0]); ++i)
        c->coeffs[i] = 0;

    signs = 0;
    for (i = 0; i < 8; ++i)
        signs |= (uint64_t) sig[sizeof(c->coeffs) / sizeof(c->coeffs[0]) / 8 + i] << 8 * i;

    /* Extra sign bits are zero for strong unforgeability */
    if (signs >> 60)
        return 1;

    for (i = 0; i < sizeof(c->coeffs) / sizeof(c->coeffs[0]) / 8; ++i) {
        for (j = 0; j < 8; ++j) {
            if ((sig[i] >> j) & 0x01) {
                c->coeffs[8 * i + j] = 1;
                c->coeffs[8 * i + j] ^= -(signs & 1) & (1 ^ (BR_DILITHIUM_THIRD_PARTY_Q - 1));
                signs >>= 1;
            }
        }
    }

    return 0;
}
