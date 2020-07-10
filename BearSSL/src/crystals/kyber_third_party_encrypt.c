#include "inner.h"
#include "ThirdParty/inc/kyber_poly.h"
#include "ThirdParty/inc/kyber_polyvec.h"
#include "ThirdParty/inc/kyber_cbd.h"
#include "ThirdParty/inc/kyber_reduce.h"

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r:          pointer to output buffer
*              - unsigned int len:    requested number of 16-bit integers
*                                     (uniform mod q)
*              - const uint8_t *buf:  pointer to input buffer
*                                     (assumed to be uniform random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
// TODO remove magic number
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen) {
    unsigned int ctr, pos;
    uint16_t val;

    ctr = pos = 0;
    while (ctr < len && pos + 2 <= buflen) {
        val = buf[pos] | ((uint16_t) buf[pos + 1] << 8);
        pos += 2;

        if (val < 19 * BR_KYBER_THIRD_PARTY_Q) {
            val -= (val >> 12) * BR_KYBER_THIRD_PARTY_Q; // Barrett reduction
            r[ctr++] = (int16_t) val;
        }
    }

    return ctr;
}

#define GEN_MATRIX_NBLOCKS ((2 * 256 * (1U << 16) / (19 * BR_KYBER_THIRD_PARTY_Q) + 168))

// TODO check polyvec matrix length validity
static void gen_matrix_row(br_kyber_third_party_polyvec *a, size_t col_nb, const uint8_t *seed, size_t seedlen) {
    unsigned int ctr, j;
    uint8_t buf[GEN_MATRIX_NBLOCKS];
    br_shake_context sc;


    for (j = 0; j < a->veclen; j++) {
        // Reset the shake state for run
        br_shake_init(&sc, 128);
        br_shake_inject(&sc, seed, seedlen);
        br_shake_inject(&sc, &col_nb, 1);
        br_shake_inject(&sc, &j, 1);
        br_shake_flip(&sc, 0);
        br_shake_produce(&sc, buf, GEN_MATRIX_NBLOCKS);
        ctr = rej_uniform(a->vec[j].coeffs, 256, buf, sizeof(buf));

        while (ctr < 256) {
            br_shake_produce(&sc, buf, sc.rate);
            ctr += rej_uniform(a->vec[j].coeffs + ctr, 256 - ctr, buf, sc.rate);
        }
    }
}

#ifdef KYBER_PRINT_ENC
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
#define polyarr_to_polyvec(dst, prev, size) dst.vec = prev.vec + prev.veclen; dst.veclen = size;

uint32_t br_kyber_third_party_encrypt(const br_prng_class **rng_ctx,
                                      const br_kyber_public_key *pk,
                                      void *ct, size_t ct_max_len,
                                      void *ss, size_t ss_len) {
    unsigned int i;
    // 2 X buff, 2 X coins
    unsigned char tmp[4 * 32];
    unsigned char tmp2[2 * 256 / 4];
    unsigned char ctr = 0;

    // We need at least 5 polyvect, of at least count polynomials.
    // Thus, we MUST restrict the maximal value of count a fair bit
    // Due to kyber1024 begin the maximum security standard, count will be limited to 4
    br_kyber_third_party_poly temp[4 * 5];
    br_kyber_third_party_polyvec sp, pub, ep, mat_row, bp;
    br_kyber_third_party_poly v, k, epp;
    br_shake_context sc;

    if (ct_max_len < BR_KYBER_CIPHERTEXT_SIZE(pk->polynbr) ||
        ss_len < 32) {
        return 0;
    }

    // Map the polynomial vectors to the local polynomial array
    sp.vec = temp;
    sp.veclen = pk->polynbr;
    polyarr_to_polyvec(pub, sp, pk->polynbr);
    polyarr_to_polyvec(ep, pub, pk->polynbr);
    polyarr_to_polyvec(mat_row, ep, pk->polynbr);
    polyarr_to_polyvec(bp, mat_row, pk->polynbr);

    // If we received a null RNG context, we can assume this call is done for the verification phase of the decapsulation
    // If so, we can skip all non-indcpa construction related operations
    if (rng_ctx) {

        // Initialize the pre-key
        (*rng_ctx)->generate(rng_ctx, tmp, 32);

#if defined KYBER_TESTING_ENC || defined KYBER_TESTING_DEC
        // TESTING STUFFS SO THAT I CAN GET PREDICTABLE OUTPUT
        memset(tmp, KYBER_RNG_OUTPUT_FORCE, 32);
#endif
        // Don't release system RNG, so hash it
        br_shake_init(&sc, 256);
        br_shake_inject(&sc, tmp, 32);
        br_shake_flip(&sc, 1);
        br_shake_produce(&sc, tmp, 32);

        // Coin countermeasure and contributory KEM
        br_shake_init(&sc, 256);
        br_shake_inject(&sc, pk->polyvec, pk->polyveclen);
        br_shake_inject(&sc, pk->seed, pk->seedlen);
        br_shake_flip(&sc, 1);
        br_shake_produce(&sc, tmp + 32, 32);

        br_shake_init(&sc, 512);
        br_shake_inject(&sc, tmp, 64);
        br_shake_flip(&sc, 1);
        br_shake_produce(&sc, tmp + 64, 64);

    } else {
        // we also use the shared secret field of the encrypt function to pass the coins as well
        // as the ciphertext field to pass the message
        memcpy(tmp, ss, ss_len);
    }

    // unpack the public key
    br_kyber_third_party_polyvec_frombytes(&pub, pk->polyvec);

    // create a polynomial from a message
    br_kyber_third_party_poly_frommsg(&k, tmp);

    // Initialize secret polyvec
    for (i = 0; i < sp.veclen; i++, ctr++) {
        br_shake_init(&sc, 256);
        br_shake_inject(&sc, tmp + 32 * 3, 32);
        br_shake_inject(&sc, &ctr, 1);
        br_shake_flip(&sc, 0);
        br_shake_produce(&sc, tmp2, 2 * 256 / 4);
        br_kyber_third_party_cbd(&sp.vec[i], tmp2);
    }



    // Initialize the ephemeral polyvec
    for (i = 0; i < ep.veclen; i++, ctr++) {
        br_shake_init(&sc, 256);
        br_shake_inject(&sc, tmp + 32 * 3, 32);
        br_shake_inject(&sc, &ctr, 1);
        br_shake_flip(&sc, 0);
        br_shake_produce(&sc, tmp2, 2 * 256 / 4);
        br_kyber_third_party_cbd(&ep.vec[i], tmp2);
    }

    // Initialize the ephemeral public polynomial

    br_shake_init(&sc, 256);
    br_shake_inject(&sc, tmp + 32 * 3, 32);
    br_shake_inject(&sc, &ctr, 1);
    br_shake_flip(&sc, 0);
    br_shake_produce(&sc, tmp2, 2 * 256 / 4);
    br_kyber_third_party_cbd(&epp, tmp2);

    br_kyber_third_party_polyvec_ntt(&sp);


    // matrix-vector multiplication with the transposed matrix
    for (i = 0; i < pub.veclen; i++) {
        gen_matrix_row(&mat_row, i, pk->seed, pk->seedlen);
        br_kyber_third_party_polyvec_pointwise_acc_montgomery(&bp.vec[i], &mat_row, &sp);
    }

    br_kyber_third_party_polyvec_pointwise_acc_montgomery(&v, &pub, &sp);

    br_kyber_third_party_polyvec_invntt_tomont(&bp);
    br_kyber_third_party_poly_invntt_tomont(&v);


    br_kyber_third_party_polyvec_add(&bp, &bp, &ep);
    br_kyber_third_party_poly_add(&v, &v, &epp);
    br_kyber_third_party_poly_add(&v, &v, &k);
    br_kyber_third_party_polyvec_reduce(&bp);
    br_kyber_third_party_poly_reduce(&v);

    // pack the ciphertext (we remove to the ciphertext size the compressed polynomial size)
    br_kyber_third_party_polyvec_compress(ct, pk->polynbr, &bp);
    br_kyber_third_party_poly_compress(ct + BR_KYBER_CIPHERTEXT_SIZE(pk->polynbr) - ((pk->polynbr + 1) * 32),
                                       pk->polynbr, &v);

    // Similarly as before, if we didn't get an RNG context, we can assume we're in the decapsulation verification phase,
    // thus, we can return at this point, since we have the ciphertext ready to return
    // The 0 return code is intentional, to make it appear as if the function failed
    if (!rng_ctx) {
        return 0;
    }

    // overwrite coins with hash of ciphertext
    br_shake_init(&sc, 256);
    br_shake_inject(&sc, ct, BR_KYBER_CIPHERTEXT_SIZE(pk->polynbr));
    br_shake_flip(&sc, 1);
    br_shake_produce(&sc, tmp + 3 * 32, 32);

    // output final ciphertext
    br_shake_init(&sc, 256);
    br_shake_inject(&sc, tmp + 64, 64);
    br_shake_flip(&sc, 0);
    br_shake_produce(&sc, ss, 32);

#ifdef KYBER_PRINT_ENC
    printf("////////////// ENC ///////////////\n");
    // Print the full memory contents of the ciphertext and shared secret
    printf("ciphertext (%ld bytes):\n", BR_KYBER_CIPHERTEXT_SIZE(bp.veclen));
    print_hex_memory(ct, BR_KYBER_CIPHERTEXT_SIZE(bp.veclen));
    printf("shared secret (ENC) (%d bytes):\n", 32);
    print_hex_memory(ss, 32);
    printf("//////////// END ENC /////////////\n");
#endif

#ifdef KYBER_TESTING_ENC
    exit(-1);
#endif

    return BR_KYBER_CIPHERTEXT_SIZE(pk->polynbr);
}