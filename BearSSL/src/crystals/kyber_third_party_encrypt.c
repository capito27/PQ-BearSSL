#include "inner.h"
#include "ThirdParty/inc/tiny_sha3.h"
#include "ThirdParty/inc/common_poly.h"
#include "ThirdParty/inc/common_polyvec.h"
#include "ThirdParty/inc/kyber_cbd.h"

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
// TODO remove magic number 3329
static unsigned int rej_uniform_col(int16_t *r,
                                    unsigned int len,
                                    const uint8_t *buf,
                                    unsigned int buflen) {
    unsigned int ctr, pos;
    uint16_t val;

    ctr = pos = 0;
    while (ctr < len && pos + 2 <= buflen) {
        val = buf[pos] | ((uint16_t) buf[pos + 1] << 8);
        pos += 2;

        if (val < 19 * 3329) {
            val -= (val >> 12) * 3329; // Barrett reduction
            r[ctr++] = (int16_t) val;
        }
    }

    return ctr;
}

#define GEN_MATRIX_NBLOCKS ((2*256*(1U << 16)/(19*3329) \
                             + 168))

// TODO check polyvec matrix length validity, remove magic numbers
void gen_matrix_col(polyvec *a, size_t col_nb, const uint8_t *seed, size_t seedlen) {
    unsigned int ctr, j;
    uint8_t buf[GEN_MATRIX_NBLOCKS];
    br_shake_context sc;


    for (j = 0; j < a->veclen; j++) {
        // Reset the shake state for run
        br_shake_init(&sc, 128);
        br_shake_inject(&sc, seed, seedlen);
        br_shake_inject(&sc, &col_nb, 1);
        br_shake_inject(&sc, &j, 1);
        br_shake_flip(&sc);
        br_shake_produce(&sc, buf, GEN_MATRIX_NBLOCKS);
        ctr = rej_uniform_col(a->vec[j].coeffs, 256, buf, sizeof(buf));

        while (ctr < 256) {
            br_shake_produce(&sc, buf, sc.rate);
            ctr += rej_uniform_col(a->vec[j].coeffs + ctr, 256 - ctr, buf, sc.rate);
        }
    }
}

uint32_t
br_kyber_third_party_encrypt(const br_prng_class **rng_ctx,
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
    poly temp[4 * 5];
    polyvec sp, pub, ep, at, bp;
    poly v, k, epp;
    br_shake_context sc;
    sha3_ctx_t sha3ctx;

    if (ct_max_len < BR_KYBER_CIPHERTEXT_SIZE(BR_KYBER_POLYVEC_COUNT(pk->polyveclen)) ||
        ss_len < 32) {
        return -1;
    }
    sp.vec = temp;
    sp.veclen = BR_KYBER_POLYVEC_COUNT(pk->polyveclen);
    pub.vec = temp + 4;
    pub.veclen = BR_KYBER_POLYVEC_COUNT(pk->polyveclen);
    ep.vec = temp + 8;
    ep.veclen = BR_KYBER_POLYVEC_COUNT(pk->polyveclen);
    at.vec = temp + 12;
    at.veclen = BR_KYBER_POLYVEC_COUNT(pk->polyveclen);
    bp.vec = temp + 16;
    bp.veclen = BR_KYBER_POLYVEC_COUNT(pk->polyveclen);

    // If we received a null RNG context, we can assume this call is done for the verification phase of the decapsulation
    // If so, we can skip all non-indcpa construction related operations
    if (rng_ctx) {

        // Initialize the pre-key
        (*rng_ctx)->generate(rng_ctx, tmp, 32);

#ifdef TESTING_ENC
        // TESTING STUFFS SO THAT I CAN GET PREDICTABLE OUTPUT
        memset(tmp, 0, 32);
#endif
#ifdef TESTING_DEC
        // TESTING STUFFS SO THAT I CAN GET PREDICTABLE OUTPUT
        memset(tmp, 0, 32);
#endif

        sha3(tmp, 32, tmp, 32);

        // Coin countermeasure and contributory KEM
        sha3_init(&sha3ctx, 32);
        sha3_update(&sha3ctx, pk->polyvec, pk->polyveclen);
        sha3_update(&sha3ctx, pk->seed, sizeof(pk->seed));
        sha3_final(tmp + 32, &sha3ctx);

        sha3(tmp, 64, tmp + 64, 64);
    } else {
        // we also use the ss field of the encrypt function to pass the coins as well as the ciphertext field to pass
        // the message
        memcpy(tmp, ss, ss_len);
    }

    // unpack the public key
    polyvec_frombytes(&pub, pk->polyvec, pk->polyveclen);

    // create a polynomial from a message
    poly_frommsg(&k, tmp, 32);

    //Initialize secret polyvec
    for (i = 0; i < sp.veclen; i++, ctr++) {
        br_shake_init(&sc, 256);
        br_shake_inject(&sc, tmp + 32 * 3, 32);
        br_shake_inject(&sc, &ctr, 1);
        br_shake_flip(&sc);
        br_shake_produce(&sc, tmp2, 2 * 256 / 4);
        br_kyber_cbd(&sp.vec[i], tmp2, 2 * 256 / 4);
    }

    //Initialize the ephemeral polyvec
    for (i = 0; i < ep.veclen; i++, ctr++) {
        br_shake_init(&sc, 256);
        br_shake_inject(&sc, tmp + 32 * 3, 32);
        br_shake_inject(&sc, &ctr, 1);
        br_shake_flip(&sc);
        br_shake_produce(&sc, tmp2, 2 * 256 / 4);
        br_kyber_cbd(&ep.vec[i], tmp2, 2 * 256 / 4);
    }

    //Initialize the ephemeral public polynome

    br_shake_init(&sc, 256);
    br_shake_inject(&sc, tmp + 32 * 3, 32);
    br_shake_inject(&sc, &ctr, 1);
    br_shake_flip(&sc);
    br_shake_produce(&sc, tmp2, 2 * 256 / 4);
    br_kyber_cbd(&epp, tmp2, 2 * 256 / 4);

    polyvec_ntt(&sp);

    // matrix-vector multiplication
    for (i = 0; i < pub.veclen; i++) {
        gen_matrix_col(&at, i, pk->seed, sizeof(pk->seed));
        polyvec_pointwise_acc_montgomery(&bp.vec[i], &at, &sp);
    }

    polyvec_pointwise_acc_montgomery(&v, &pub, &sp);

    polyvec_invntt_tomont(&bp);
    poly_invntt_tomont(&v);

    polyvec_add(&bp, &bp, &ep);
    poly_add(&v, &v, &epp);
    poly_add(&v, &v, &k);
    polyvec_reduce(&bp);
    poly_reduce(&v);

    // pack the ciphertext (we remove to the ciphertext size the compressed polynom size)
    polyvec_compress(ct, BR_KYBER_CIPHERTEXT_SIZE(bp.veclen) - ((bp.veclen + 1) * 32), &bp);
    poly_compress(ct + BR_KYBER_CIPHERTEXT_SIZE(bp.veclen) - ((bp.veclen + 1) * 32), ((bp.veclen + 1) * 32), &v);

    // Similarly as before, if we didn't get an RNG context, we can assume we're in the decapsulation verification phase,
    // thus, we can return at this point, since we have the ciphertext ready to return
    if (!rng_ctx) {
        return 0;
    }

    // overwrite coins with hash of ciphertext
    sha3(ct, BR_KYBER_CIPHERTEXT_SIZE(bp.veclen), tmp + 3 * 32, 32);

    // output final ciphertext
    br_shake_init(&sc, 256);
    br_shake_inject(&sc, tmp + 64, 64);
    br_shake_flip(&sc);
    br_shake_produce(&sc, ss, 32);

#ifdef TESTING_ENC
    // Print the full memory contents of the private and public key
    printf("ciphertext (%d bytes):\n", BR_KYBER_CIPHERTEXT_SIZE(bp.veclen));
    enc_print_hex_memory(ct, BR_KYBER_CIPHERTEXT_SIZE(bp.veclen));
    printf("shared secret (%d bytes):\n", 32);
    enc_print_hex_memory(ss, 32);

    exit(-1);
}

void enc_print_hex_memory(void *mem, size_t length) {
    int i;
    unsigned char *p = (unsigned char *) mem;
    for (i = 0; i < length; i++) {
        printf("0x%02x ", p[i]);
        if ((i % 16 == 15) && i < length)
            printf("\n");
    }
    printf("\n");
#endif
#ifdef TESTING_DEC
    // Print the full memory contents of the private and public key
    printf("shared secret (ENC) (%d bytes):\n", 32);
    enc_print_hex_memory(ss, 32);
}

void enc_print_hex_memory(void *mem, size_t length) {
    int i;
    unsigned char *p = (unsigned char *) mem;
    for (i = 0; i < length; i++) {
        printf("0x%02x ", p[i]);
        if ((i % 16 == 15) && i < length)
            printf("\n");
    }
    printf("\n");
#endif
    return 0;
}