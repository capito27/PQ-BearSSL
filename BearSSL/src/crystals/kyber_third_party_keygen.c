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
static unsigned int rej_uniform_row(int16_t *r,
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
void gen_matrix_row(polyvec *a, size_t row_nb, const uint8_t *seed, size_t seedlen) {
    unsigned int ctr, j;
    uint8_t buf[GEN_MATRIX_NBLOCKS];
    br_shake_context sc;


    for (j = 0; j < a->veclen; j++) {
        // Reset the shake state for run
        br_shake_init(&sc, 128);
        br_shake_inject(&sc, seed, seedlen);
        br_shake_inject(&sc, &j, 1);
        br_shake_inject(&sc, &row_nb, 1);
        br_shake_flip(&sc);
        br_shake_produce(&sc, buf, GEN_MATRIX_NBLOCKS);
        ctr = rej_uniform_row(a->vec[j].coeffs, 256, buf, sizeof(buf));

        while (ctr < 256) {
            br_shake_produce(&sc, buf, sc.rate);
            ctr += rej_uniform_row(a->vec[j].coeffs + ctr, 256 - ctr, buf, sc.rate);
        }
    }
}

uint32_t
br_kyber_third_party_keygen(const br_prng_class **rng_ctx,
                            br_kyber_private_key *sk, void *kbuf_priv,
                            br_kyber_public_key *pk, void *kbuf_pub,
                            unsigned count) {
    unsigned int i, ctr;
    unsigned char tmp[2 * 32];
    unsigned char tmp2[2 * 256 / 4];
    // We need at least 4 polyvect, of at least count polynomials.
    // Thus, we MUST restrict the maximal value of count a fair bit
    // Due to kyber1024 begin the maximum security standard, count will be limited to 4
    poly temp[4 * 4];
    polyvec priv, pub, e, a;
    br_shake_context sc;
    sha3_ctx_t sha3ctx;

    if (count < 2 || count > 4) {
        return -1;
    }

    sk->polyvec = kbuf_priv;
    sk->polyveclen = BR_KYBER_POLYVEC_SIZE(count);
    sk->pubkey = pk;

    pk->polyveclen = BR_KYBER_POLYVEC_SIZE(count);
    pk->polyvec = kbuf_pub;

    priv.vec = temp;
    priv.veclen = count;

    pub.vec = temp + 4;
    pub.veclen = count;

    e.vec = temp + 8;
    e.veclen = count;

    a.vec = temp + 12;
    a.veclen = count;

    (*rng_ctx)->generate(rng_ctx, tmp, 32);

#ifdef TESTING_KEYGEN
    // TESTING STUFFS SO THAT I CAN GET PREDICTABLE OUTPUT
        memset(tmp, 0, 32);
#endif
#ifdef TESTING_ENC
    // TESTING STUFFS SO THAT I CAN GET PREDICTABLE OUTPUT
        memset(tmp, 0, 32);
#endif
#ifdef TESTING_DEC
    // TESTING STUFFS SO THAT I CAN GET PREDICTABLE OUTPUT
        memset(tmp, 0, 32);
#endif

    sha3_init(&sha3ctx, 2 * 32);
    sha3_update(&sha3ctx, tmp, 32);
    sha3_final(tmp, &sha3ctx);



    //Initialize the secret key
    for (i = 0; i < priv.veclen; i++, ctr++) {
        br_shake_init(&sc, 256);
        br_shake_inject(&sc, tmp + 32, 32);
        br_shake_inject(&sc, &ctr, 1);
        br_shake_flip(&sc);
        br_shake_produce(&sc, tmp2, 2 * 256 / 4);
        br_kyber_cbd(&priv.vec[i], tmp2, 2 * 256 / 4);
    }

    //Initialize the ephemeral polyvec
    for (i = 0; i < e.veclen; i++, ctr++) {
        br_shake_init(&sc, 256);
        br_shake_inject(&sc, tmp + 32, 32);
        br_shake_inject(&sc, &ctr, 1);
        br_shake_flip(&sc);
        br_shake_produce(&sc, tmp2, 2 * 256 / 4);
        br_kyber_cbd(&e.vec[i], tmp2, 2 * 256 / 4);
    }

    polyvec_ntt(&priv);
    polyvec_ntt(&e);

    // matrix-vector multiplication
    for (i = 0; i < pub.veclen; i++) {
        gen_matrix_row(&a, i, tmp, 32);
        polyvec_pointwise_acc_montgomery(&pub.vec[i], &a, &priv);
        poly_tomont(&pub.vec[i]);
    }

    polyvec_add(&pub, &pub, &e);
    polyvec_reduce(&pub);

    // Pack the public key
    polyvec_tobytes(kbuf_pub, BR_KYBER_POLYVEC_SIZE(count), &pub);
    memcpy(pk->seed, tmp, sizeof(pk->seed));

    // Pack the private key
    polyvec_tobytes(kbuf_priv, BR_KYBER_POLYVEC_SIZE(count), &priv);
    sha3_init(&sha3ctx, 32);
    sha3_update(&sha3ctx, kbuf_pub, BR_KYBER_POLYVEC_SIZE(count));
    sha3_update(&sha3ctx, pk->seed, sizeof(pk->seed));
    sha3_final(sk->hpk, &sha3ctx);

    (*rng_ctx)->generate(rng_ctx, sk->z, 32);

#ifdef TESTING_KEYGEN
    // TESTING STUFFS SO THAT I CAN GET PREDICTABLE OUTPUT
        memset(sk->z, 0, 32);
#endif
#ifdef TESTING_ENC
    // TESTING STUFFS SO THAT I CAN GET PREDICTABLE OUTPUT
        memset(sk->z, 0, 32);
#endif
#ifdef TESTING_DEC
    // TESTING STUFFS SO THAT I CAN GET PREDICTABLE OUTPUT
        memset(sk->z, 0, 32);
#endif

#ifdef TESTING_KEYGEN
    // Print the full memory contents of the private and public key
    printf("public key (%d bytes):\n", pk->polyveclen);
    keygen_print_hex_memory(pk->polyvec, pk->polyveclen);
    printf("public key seed (%d bytes):\n", sizeof(pk->seed));
    keygen_print_hex_memory(pk->seed, sizeof(pk->seed));

    printf("private key (%d bytes):\n", sk->polyveclen);
    keygen_print_hex_memory(sk->polyvec, sk->polyveclen);
    printf("private key hpk (%d bytes):\n", sizeof(sk->hpk));
    keygen_print_hex_memory(sk->hpk, sizeof(sk->hpk));
    printf("private key z (%d bytes):\n", sizeof(sk->z));
    keygen_print_hex_memory(sk->z, sizeof(sk->z));
    exit(-1);
}

void keygen_print_hex_memory(void *mem, size_t length) {
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