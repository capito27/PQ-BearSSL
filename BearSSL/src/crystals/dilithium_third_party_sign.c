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

#ifdef DILITHIUM_PRINT_SIGN
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
#define omega(mode) ((mode) <= 3 ? 48 + 16 * (mode) : 120)

uint32_t br_dilithium_third_party_sign(const br_prng_class **rnd,
                                       const br_dilithium_private_key *sk,
                                       void *sig, size_t sig_max_len,
                                       const void *msg, size_t msg_len) {
    unsigned int i, n;
    // 2 seeds
    unsigned char seeds[48 * 2];
    // We need at least 5 independent polyvec.
    // Thus, we MUST restrict the maximal value of "mode" a fair bit
    // Due to Dilithium4 being the maximum security standard, mode will be limited to 4,
    // thus 1 polyvec of 5 polynomials each and 4 vectors of 6 polynomials each.
    br_dilithium_third_party_poly tmp[4 * 6 + 5];

    uint16_t nonce = 0;
    unsigned char *mu, *rhoprime;
    br_dilithium_third_party_poly c;
    br_dilithium_third_party_polyvec s1, y, z, t0, s2, w1, w0, h;
    br_shake_context sc;
#ifdef BR_DILITHIUM_FAST_SIGN
    // Due to the moderately high likelyhood of requiring to recompute the signature, it can be quite advantageous to
    // store a precomputed matrix once generated
    // (this is quite a nice performance improvement, but does cost a non-negligible amount of memory)
    br_dilithium_third_party_poly matrix_storage[5 * 6];
    br_dilithium_third_party_polyvec matrix[6];
    for (i = 0; i < sk->mode + 2u; i++){
        matrix[i].vec = matrix_storage + i*(sk->mode + 1);
        matrix[i].polylen = sk->mode + 1;
    }
#else
    br_dilithium_third_party_polyvec mat_row;
#endif

    if (sig_max_len < BR_DILITHIUM_SIGNATURE_SIZE(sk->mode)) {
        return 0;
    }
    mu = seeds;
    rhoprime = seeds + 48;

    // Map local polynomial vectors to local polynomial array
    w0.vec = tmp;
    w0.polylen = sk->mode + 2;
    polyarr_to_polyvec(w1, w0, sk->mode + 2);
    polyarr_to_polyvec(h, w1, sk->mode + 2);
    polyarr_to_polyvec(t0, h, sk->mode + 2);
    polyarr_to_polyvec(y, t0, sk->mode + 1);
    // z can share h's inner polynomial array, due to there being no overlap on their usage
    polyarr_to_polyvec(z, w1, sk->mode + 1);
    // s2 can share t0's inner polynomial array, due to there bing no overlap on their usage
    polyarr_to_polyvec(s2, h, sk->mode + 2);
    // s1 can share t0's inner polynomial array, due to there being no overlap on their usage
    polyarr_to_polyvec(s1, h, sk->mode + 1);
#ifndef BR_DILITHIUM_FAST_SIGN
    // mat_row can share t0's inner polynomial array, due to there being no overlap on their usage
    polyarr_to_polyvec(mat_row, h, sk->mode + 1);
#endif

    // Compute CHR(tr, msg)
    br_shake_init(&sc, 256);
    br_shake_inject(&sc, sk->tr, sk->trlen);
    br_shake_inject(&sc, msg, msg_len);
    br_shake_flip(&sc, 0);
    br_shake_produce(&sc, mu, 48);

    // Randomise rhoprime (support for non-randomised signing is disabled)
    (*rnd)->generate(rnd, rhoprime, 48);

#if defined DILITHIUM_TESTING_SIGN || defined DILITHIUM_TESTING_VERIFY
    // TESTING STUFFS SO THAT I CAN GET PREDICTABLE OUTPUT
    memset(rhoprime, DILITHIUM_RNG_OUTPUT_FORCE, 48);
#endif

#ifdef BR_DILITHIUM_FAST_SIGN
    // Precompute the matrix before the matrix-vector multiplication
    for (i = 0; i < sk->mode + 2u; i++){
        gen_matrix_row(&matrix[i], i, sk->rho, sk->rholen);
    }
#endif

    // Rejection based infinite loop
    for (;;) {
        // Sample intermediate vector y and copy it to z
        for (i = 0; i < y.polylen; ++i) {
            br_dilithium_third_party_poly_uniform_gamma1m1(&y.vec[i], rhoprime, 48, nonce++);
            memcpy(z.vec[i].coeffs, y.vec[i].coeffs, sizeof(y.vec[i].coeffs));
        }

        // Apply the matrix-vector multiplication
        br_dilithium_third_party_polyvec_ntt(&z);
        for (i = 0; i < w1.polylen; i++) {
#ifdef BR_DILITHIUM_FAST_SIGN
            br_dilithium_third_party_polyvec_pointwise_acc_invmontgomery(&w1.vec[i], &matrix[i], &z);
#else
            gen_matrix_row(&mat_row, i, sk->rho, sk->rholen);
            br_dilithium_third_party_polyvec_pointwise_acc_invmontgomery(&w1.vec[i], &mat_row, &z);
#endif
            br_dilithium_third_party_poly_reduce(&w1.vec[i]);
            br_dilithium_third_party_poly_invntt_montgomery(&w1.vec[i]);
        }

        // Decompose w and call the random oracle
        br_dilithium_third_party_polyvec_csubq(&w1);
        br_dilithium_third_party_polyvec_decompose(&w1, &w0, &w1);

        challenge(&c, mu, 48, &w1);
        // Pack c into the signature before computing z,
        // thus removing the need to copy or revert it later on
        br_dilithium_third_party_pack_sig(sig, NULL, NULL, &c, sk->mode);

        br_dilithium_third_party_poly_ntt(&c);

        // Unpack and transform s1 from the secret key
        br_dilithium_third_party_unpack_sk(&s1, NULL, NULL, sk);
        br_dilithium_third_party_polyvec_ntt(&s1);

        // Compute z, reject if it reveals secret
        for (i = 0; i < z.polylen; ++i) {
            br_dilithium_third_party_poly_pointwise_invmontgomery(&z.vec[i], &c, &s1.vec[i]);
            br_dilithium_third_party_poly_invntt_montgomery(&z.vec[i]);
        }
        br_dilithium_third_party_polyvec_add(&z, &z, &y);
        br_dilithium_third_party_polyvec_freeze(&z);
        if (br_dilithium_third_party_polyvec_chknorm(&z, BR_DILITHIUM_THIRD_PARTY_GAMMA1 - beta(sk->mode))) {
            continue;
        }

        // At this point, z can be packed, and its inner polynomial array re-purposed for h
        br_dilithium_third_party_pack_sig(sig, &z, NULL, NULL, sk->mode);

        // unpack and transform s2 from the secret key
        br_dilithium_third_party_unpack_sk(NULL, &s2, NULL, sk);
        br_dilithium_third_party_polyvec_ntt(&s2);

        // Check that subtracting c * s2 does not change high bits of w and low bits
        // do not reveal secret information (reject it if it does)
        for (i = 0; i < h.polylen; ++i) {
            br_dilithium_third_party_poly_pointwise_invmontgomery(&h.vec[i], &c, &s2.vec[i]);
            br_dilithium_third_party_poly_invntt_montgomery(&h.vec[i]);
        }
        br_dilithium_third_party_polyvec_sub(&w0, &w0, &h);
        br_dilithium_third_party_polyvec_freeze(&w0);
        if (br_dilithium_third_party_polyvec_chknorm(&w0, BR_DILITHIUM_THIRD_PARTY_GAMMA2 - beta(sk->mode))) {
            continue;
        }
        // unpack and transform t0 from the secret key
        br_dilithium_third_party_unpack_sk(NULL, NULL, &t0, sk);
        br_dilithium_third_party_polyvec_ntt(&t0);

        // Compute hints for w1 (reject the signature if too much information is available)
        for (i = 0; i < h.polylen; ++i) {
            br_dilithium_third_party_poly_pointwise_invmontgomery(&h.vec[i], &c, &t0.vec[i]);
            br_dilithium_third_party_poly_invntt_montgomery(&h.vec[i]);
        }
        br_dilithium_third_party_polyvec_csubq(&h);

        if (br_dilithium_third_party_polyvec_chknorm(&h, BR_DILITHIUM_THIRD_PARTY_GAMMA2)) {
            continue;
        }

        br_dilithium_third_party_polyvec_add(&w0, &w0, &h);
        br_dilithium_third_party_polyvec_csubq(&w0);
        n = br_dilithium_third_party_polyvec_make_hint(&h, &w0, &w1);
        if (n > (unsigned) omega(sk->mode)) {
            continue;
        }

        // Finish packing the signature
        br_dilithium_third_party_pack_sig(sig, NULL, &h, NULL, sk->mode);

#ifdef DILITHIUM_PRINT_SIGN
        printf("////////////// SIGN //////////////\n");
        // Print the full memory contents of the signature
        printf("sig : z (%d bytes):\n", (sk->mode + 1) * 640);
        print_hex_memory(sig, (sk->mode + 1) * 640);
        printf("sig : h (%d bytes):\n", omega(sk->mode) + sk->mode + 2);
        print_hex_memory(sig + (sk->mode + 1) * 640, omega(sk->mode) + sk->mode + 2);
        printf("sig : c (%d bytes):\n", (256/8 + 8));
        print_hex_memory(sig + BR_DILITHIUM_SIGNATURE_SIZE(sk->mode) - (256/8 + 8), (256/8 + 8));
        printf("//////////// END SIGN ////////////\n");
#endif

#ifdef DILITHIUM_TESTING_SIGN
        exit(-1);
#endif

        return BR_DILITHIUM_SIGNATURE_SIZE(sk->mode);
    }
}
