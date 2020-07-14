#include "inner.h"
#include "ThirdParty/inc/dilithium_poly.h"
#include "ThirdParty/inc/dilithium_polyvec.h"
#include "ThirdParty/inc/dilithium_packing.h"
#include "ThirdParty/inc/dilithium_rounding.h"


/*************************************************
* Name:        challenge
*
* Description: Implementation of H. Samples polynomial with 60 nonzero
*              coefficients in {-1,1} using the output stream of
*              SHAKE256(mu|w1).
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const uint8_t mu[]: byte array containing mu
*              - const polyvec *w1: pointer to vector w1
**************************************************/
static void challenge(br_dilithium_third_party_poly *c,
                      const unsigned char *mu, size_t mulen,
                      const br_dilithium_third_party_polyvec *w1) {
    unsigned int i, b, pos;
    uint64_t signs;
    // Buffer need to hold the largest w1 vector possible, thus it must hold 6 packed polyw1
    uint8_t buf[48 + 6 * 128];
    br_shake_context sc;

    for (i = 0; i < mulen; ++i)
        buf[i] = mu[i];
    for (i = 0; i < w1->polylen; ++i)
        br_dilithium_third_party_polyw1_pack(buf + 48 + i * 128, &w1->vec[i]);

    // Compute SHAKE256(mu|w1)
    br_shake_init(&sc, 256);
    br_shake_inject(&sc, buf, 48 + w1->polylen * 128);
    br_shake_flip(&sc, 0);
    br_shake_produce(&sc, buf, sc.rate);

    signs = 0;
    for (i = 0; i < 8; ++i)
        signs |= (uint64_t) buf[i] << 8 * i;

    pos = 8;

    for (i = 0; i < sizeof(c->coeffs) / sizeof(c->coeffs[0]); ++i)
        c->coeffs[i] = 0;

    for (i = 196; i < sizeof(c->coeffs) / sizeof(c->coeffs[0]); ++i) {
        do {
            if (pos >= sc.rate) {
                br_shake_produce(&sc, buf, sc.rate);
                pos = 0;
            }

            b = buf[pos++];
        } while (b > i);

        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = 1;
        c->coeffs[b] ^= -((uint32_t) signs & 1) & (1 ^ (BR_DILITHIUM_THIRD_PARTY_Q - 1));
        signs >>= 1;
    }
}

static void gen_matrix_row(br_dilithium_third_party_polyvec *a, uint8_t row_nb, const uint8_t *seed, size_t seedlen) {
    uint8_t j;
    for (j = 0; j < a->polylen; j++) {
        br_dilithium_third_party_poly_uniform(&a->vec[j], seed, seedlen, (row_nb << 8) + j);
    }
}

#ifdef DILITHIUM_PRINT_VERIFY
#include <stdio.h>
static void print_hex_memory(void *mem, size_t length) {
    size_t i;
    unsigned char *p = (unsigned char *) mem;
    for (i = 0; i < length; i++) {
        printf("0x%02x ", p[i]);
        if ((i % 16 == 15) && i < length)
            printf("\n");
    }
    printf("\n");
}
#endif

// Macro to easily map a buffer segment to a polyvec
#define polyarr_to_polyvec(dst, prev, size) dst.vec = prev.vec + prev.polylen; dst.polylen = size;

#define beta(mode) ((mode) <= 3 ? 425 - 50 * (mode): 175)

uint32_t br_dilithium_third_party_vrfy(const br_dilithium_public_key *pk,
                                         const void *msg, size_t msg_len,
                                         const void *sig, size_t sig_len) {
    unsigned int i;
    uint8_t mu[48];
    br_dilithium_third_party_poly c, cp;
    br_dilithium_third_party_polyvec mat_row, z, t1, h, w1;
    // We need at least 5 polyvec.
    // Thus, we MUST restrict the maximal value of "mode" a fair bit
    // Due to Dilithium4 begin the maximum security standard, mode will be limited to 4,
    // thus 2 polyvec of 5 polynomials each and 3 vectors of 6 polynomials each.

    br_dilithium_third_party_poly tmp[3 * 6 + 2 * 5];
    br_shake_context sc;

    if (sig_len != BR_DILITHIUM_SIGNATURE_SIZE(pk->mode))
        return -1;

    // Map local polynomial vectors to local polynomial array
    mat_row.vec = tmp;
    mat_row.polylen = pk->mode + 1;
    polyarr_to_polyvec(z, mat_row, pk->mode + 1);
    polyarr_to_polyvec(t1, z, pk->mode + 2);
    polyarr_to_polyvec(h, t1, pk->mode + 2);
    polyarr_to_polyvec(w1, h, pk->mode + 2);


    br_dilithium_third_party_unpack_pk(&t1, pk);
    if (br_dilithium_third_party_unpack_sig(&z, &h, &c, sig, pk->mode))
        return -1;
    if (br_dilithium_third_party_polyvec_chknorm(&z, BR_DILITHIUM_THIRD_PARTY_GAMMA1 - beta(pk->mode)))
        return -1;

    /* Compute CRH(CRH(rho, t1), msg) */
    br_shake_init(&sc, 256);
    br_shake_inject(&sc, pk->rho, pk->rholen);
    br_shake_inject(&sc, pk->t1, pk->t1len);
    br_shake_flip(&sc, 0);
    br_shake_produce(&sc, mu, sizeof mu);

    br_shake_init(&sc, 256);
    br_shake_inject(&sc, mu, sizeof mu);
    br_shake_inject(&sc, msg, msg_len);
    br_shake_flip(&sc, 0);
    br_shake_produce(&sc, mu, sizeof mu);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    br_dilithium_third_party_polyvec_ntt(&z);
    for (i = 0; i < pk->mode + 2u; ++i) {
        gen_matrix_row(&mat_row, i, pk->rho, pk->rholen);
        br_dilithium_third_party_polyvec_pointwise_acc_invmontgomery(&w1.vec[i], &mat_row, &z);
    }

    memcpy(cp.coeffs, c.coeffs, sizeof cp.coeffs);
    br_dilithium_third_party_poly_ntt(&cp);
    br_dilithium_third_party_polyvec_shiftl(&t1);
    br_dilithium_third_party_polyvec_ntt(&t1);
    for (i = 0; i < pk->mode + 2u; ++i) {
        br_dilithium_third_party_poly_pointwise_invmontgomery(&t1.vec[i], &cp, &t1.vec[i]);
    }

    br_dilithium_third_party_polyvec_sub(&w1, &w1, &t1);
    br_dilithium_third_party_polyvec_reduce(&w1);
    br_dilithium_third_party_polyvec_invntt_montgomery(&w1);

    /* Reconstruct w1 */
    br_dilithium_third_party_polyvec_csubq(&w1);
    br_dilithium_third_party_polyvec_use_hint(&w1, &w1, &h);

    /* Call random oracle and verify challenge */
    challenge(&cp, mu, sizeof mu, &w1);
    for (i = 0; i < sizeof(c.coeffs) / sizeof(c.coeffs[0]); ++i)
        if (c.coeffs[i] != cp.coeffs[i])
            return -1;

#ifdef DILITHIUM_PRINT_VERIFY
    printf("///////////// VERIFY /////////////\n");
    printf("reconstructed challenge polynomial (%ld bytes) : \n", sizeof cp.coeffs);
    print_hex_memory(cp.coeffs, sizeof cp.coeffs);
    printf("/////////// END VERIFY ///////////\n");
#endif

#ifdef DILITHIUM_TESTING_VERIFY
    exit(-1);
#endif

    return 0;
}