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

#define GEN_MATRIX_NBLOCKS ((2*256*(1U << 16)/(19*BR_KYBER_THIRD_PARTY_Q) \
                             + 168))

// TODO check polyvec matrix length validity, remove magic numbers
static void gen_matrix_row(br_kyber_third_party_polyvec *a, size_t row_nb, const uint8_t *seed, size_t seedlen) {
    unsigned int ctr, j;
    uint8_t buf[GEN_MATRIX_NBLOCKS];
    br_shake_context sc;

    for (j = 0; j < a->veclen; j++) {
        // Reset the shake state for run
        br_shake_init(&sc, 128);
        br_shake_inject(&sc, seed, seedlen);
        br_shake_inject(&sc, &j, 1);
        br_shake_inject(&sc, &row_nb, 1);
        br_shake_flip(&sc, 0);
        br_shake_produce(&sc, buf, GEN_MATRIX_NBLOCKS);
        ctr = rej_uniform(a->vec[j].coeffs, 256, buf, sizeof(buf));

        while (ctr < 256) {
            br_shake_produce(&sc, buf, sc.rate);
            ctr += rej_uniform(a->vec[j].coeffs + ctr, 256 - ctr, buf, sc.rate);
        }
    }
}

#ifdef KYBER_PRINT_KEYGEN
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

// Macro to easily map contiguous buffer segments to a key section
#define buff_to_key(dst, src, size) dst = (unsigned char *) src; dst##len = size; src = (unsigned char *) src + dst##len;

// Macro to easily map contiguous buffer segments to a polyvec
#define polyarr_to_polyvec(dst, prev, size) dst.vec = prev.vec + prev.veclen; dst.veclen = size;

uint32_t br_kyber_third_party_keygen(const br_prng_class **rng_ctx,
                                     br_kyber_private_key *sk, void *kbuf_priv,
                                     br_kyber_public_key *pk, void *kbuf_pub,
                                     unsigned count) {
    unsigned int i, ctr;
    unsigned char tmp[2 * 32];
    unsigned char tmp2[2 * 256 / 4];
    // We need at least 4 polyvect, of at least count polynomials.
    // Thus, we MUST restrict the maximal value of count a fair bit
    // Due to kyber1024 begin the maximum security standard, count will be limited to 4
    br_kyber_third_party_poly temp[4 * 4];
    br_kyber_third_party_polyvec priv, pub, e, a;
    br_shake_context sc;

    if (count < 2 || count > 4) {
        return -1;
    }
    // Map private and public kbufs to key material
    buff_to_key(sk->privec, kbuf_priv, 384 * count);
    buff_to_key(sk->pubvec, kbuf_priv, 384 * count);
    buff_to_key(sk->seed, kbuf_priv, 32);
    buff_to_key(sk->hpk, kbuf_priv, 32);
    buff_to_key(sk->z, kbuf_priv, 32);
    sk->polynbr = count;
    
    if (pk) {
        buff_to_key(pk->polyvec, kbuf_pub, 384 * count);
        buff_to_key(pk->seed, kbuf_pub, 32);
        pk->polynbr = count;
    }

    // Map local polynomial vectors to the local polynomial array
    priv.vec = temp;
    priv.veclen = count;
    polyarr_to_polyvec(pub, priv, count);
    polyarr_to_polyvec(e, pub, count);
    polyarr_to_polyvec(a, e, count);

    (*rng_ctx)->generate(rng_ctx, tmp, 32);

#if defined KYBER_TESTING_KEYGEN || defined KYBER_TESTING_ENC || defined KYBER_TESTING_DEC
    // TESTING STUFFS SO THAT I CAN GET PREDICTABLE OUTPUT
        memset(tmp, KYBER_RNG_OUTPUT_FORCE, 32);
#endif

    // Hide system random by hashing it
    br_shake_init(&sc, 512);
    br_shake_inject(&sc, tmp, 32);
    br_shake_flip(&sc, 1);
    br_shake_produce(&sc, tmp, 64);

    //Initialize the secret key
    for (i = 0; i < priv.veclen; i++, ctr++) {
        br_shake_init(&sc, 256);
        br_shake_inject(&sc, tmp + 32, 32);
        br_shake_inject(&sc, &ctr, 1);
        br_shake_flip(&sc, 0);
        br_shake_produce(&sc, tmp2, 128);
        br_kyber_third_party_cbd(&priv.vec[i], tmp2);
    }

    //Initialize the ephemeral polyvec
    for (i = 0; i < e.veclen; i++, ctr++) {
        br_shake_init(&sc, 256);
        br_shake_inject(&sc, tmp + 32, 32);
        br_shake_inject(&sc, &ctr, 1);
        br_shake_flip(&sc, 0);
        br_shake_produce(&sc, tmp2, 128);
        br_kyber_third_party_cbd(&e.vec[i], tmp2);
    }

    br_kyber_third_party_polyvec_ntt(&priv);
    br_kyber_third_party_polyvec_ntt(&e);

    // matrix-vector multiplication
    for (i = 0; i < pub.veclen; i++) {
        gen_matrix_row(&a, i, tmp, 32);
        br_kyber_third_party_polyvec_pointwise_acc_montgomery(&pub.vec[i], &a, &priv);
        br_kyber_third_party_poly_tomont(&pub.vec[i]);
    }

    br_kyber_third_party_polyvec_add(&pub, &pub, &e);
    br_kyber_third_party_polyvec_reduce(&pub);

    // Pack the private key and copy the public key material
    br_kyber_third_party_polyvec_tobytes(sk->privec, &priv);
    br_kyber_third_party_polyvec_tobytes(sk->pubvec, &pub);
    memcpy(sk->seed, tmp, sk->seedlen);
    (*rng_ctx)->generate(rng_ctx, sk->z, sk->zlen);

    br_shake_init(&sc, 256);
    br_shake_inject(&sc, sk->pubvec, sk->pubveclen);
    br_shake_inject(&sc, sk->seed, sk->seedlen);
    br_shake_flip(&sc, 1);
    br_shake_produce(&sc, sk->hpk, sk->hpklen);
    
    // Pack the public key if it's provided
    if (pk) {
        memcpy(pk->seed, sk->seed, sk->seedlen);
        memcpy(pk->polyvec, sk->pubvec, sk->pubveclen);    
    }

#if defined KYBER_TESTING_KEYGEN || defined KYBER_TESTING_ENC || defined KYBER_TESTING_DEC
    // TESTING STUFFS SO THAT I CAN GET PREDICTABLE OUTPUT
        memset(sk->z, KYBER_RNG_OUTPUT_FORCE, 32);
#endif

#ifdef KYBER_PRINT_KEYGEN
    printf("///////////// KEYGEN /////////////\n");
    // Print the full memory contents of the private and public key
    printf("public key (%ld bytes):\n", sk->pubveclen);
    print_hex_memory(sk->pubvec, sk->pubveclen);
    printf("public key seed (%ld bytes):\n", sk->seedlen);
    print_hex_memory(sk->seed, sk->seedlen);

    printf("private key (%ld bytes):\n", sk->priveclen);
    print_hex_memory(sk->privec, sk->priveclen);
    printf("private key hpk (%ld bytes):\n", sk->hpklen);
    print_hex_memory(sk->hpk, sk->hpklen);
    printf("private key z (%ld bytes):\n", sk->zlen);
    print_hex_memory(sk->z, sk->zlen);
    printf("/////////// KEYGEN END ///////////\n");
#endif

#ifdef KYBER_TESTING_KEYGEN
    exit(-1);
#endif

    return 0;
}