#include "inner.h"
#include "ThirdParty/inc/dilithium_poly.h"
#include "ThirdParty/inc/dilithium_polyvec.h"
#include "ThirdParty/inc/dilithium_packing.h"

static void gen_matrix_row(br_dilithium_third_party_polyvec *a, uint8_t row_nb, const uint8_t *seed, size_t seedlen) {
    uint8_t j;
    for (j = 0; j < a->polylen; j++) {
        br_dilithium_third_party_poly_uniform(&a->vec[j], seed, seedlen, (row_nb << 8) + j);
    }
}
#ifdef DILITHIUM_PRINT_KEYGEN
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

// Valid calculation for security levels 1 through 4
#define polyeta_packed(mode) ((mode) <= 3 ? 128 : 96)

// Macro to easily map contiguous buffer segments to a key section
#define buff_to_key(dst, src, size) dst = src; dst##len = size; src += dst##len;

// Macro to easily map contiguous buffer segments to a polyvec
#define polyarr_to_polyvec(dst, prev, size) dst.vec = prev.vec + prev.polylen; dst.polylen = size;

uint32_t br_dilithium_third_party_keygen(const br_prng_class **rng_ctx,
                                         br_dilithium_private_key *sk, void *kbuf_priv,
                                         br_dilithium_public_key *pk, void *kbuf_pub,
                                         unsigned mode) {
    unsigned int i;
    uint16_t nonce;
    unsigned char tmp[3 * 32];
    unsigned eta;

    // We need at least 4 polyvect, of at least "mode+2" polynomials.
    // Thus, we MUST restrict the maximal value of count a fair bit
    // Due to Dilithium4 being the maximum security standard, mode will be limited to 4,
    // thus 3 polyvec of 6 elements and one of 5 elements
    br_dilithium_third_party_poly temp[2 * 6 + 5];
    br_dilithium_third_party_polyvec s1, s2, t1, t0, mat_row;
    br_shake_context sc;

    // Quit if the mode is invalid
    if (mode < 1 || mode > 4) {
        return -1;
    }
    nonce = 0;
    eta = mode <= 3 ? 8 - mode : 3;

    // Map the private and public buffers to the respective key regions
    if(pk){
        buff_to_key(pk->rho, kbuf_pub, 32);
        buff_to_key(pk->t1, kbuf_pub, (mode + 2) * 288);
        pk->mode = mode;
    }

    buff_to_key(sk->rho, kbuf_priv, 32);
    buff_to_key(sk->key, kbuf_priv, 32);
    buff_to_key(sk->tr, kbuf_priv, 48);
    buff_to_key(sk->s1, kbuf_priv, (mode + 1) * polyeta_packed(mode));
    buff_to_key(sk->s2, kbuf_priv, (mode + 2) * polyeta_packed(mode));
    buff_to_key(sk->t0, kbuf_priv, (mode + 2) * 448);
    sk->mode = mode;

    // Map the local polynomial vectors to the temporary poly buffer
    s1.vec = temp;
    s1.polylen = mode + 1;

    polyarr_to_polyvec(t1, s1, mode + 2);
    // make t0, s1 and mat_row share their underlying poly array, due to there being no overlap on their usage
    polyarr_to_polyvec(t0, t1, mode + 2);
    polyarr_to_polyvec(mat_row, t1, mode + 1);
    polyarr_to_polyvec(s2, t1, mode + 2);

    // Generate 96 bytes of randomness
    (*rng_ctx)->generate(rng_ctx, tmp, 3 * 32);

#if defined DILITHIUM_TESTING_KEYGEN || defined DILITHIUM_TESTING_SIGN || defined DILITHIUM_TESTING_VERIFY
    // TESTING STUFFS SO THAT I CAN GET PREDICTABLE OUTPUT
        memset(tmp, DILITHIUM_RNG_OUTPUT_FORCE, 32 * 3);
#endif

    // Initialize s1
    for (i = 0; i < s1.polylen; i++) {
        br_dilithium_third_party_poly_uniform_eta(&s1.vec[i], tmp + 32, 32, nonce++, eta);
    }

    // Pack s1 into the secret key before applying the NTT,
    // thus removing the need to copy or revert it later on
    br_dilithium_third_party_pack_sk(sk, &s1, NULL, NULL, mode);

    // Matrix-vector multiplication
    br_dilithium_third_party_polyvec_ntt(&s1);
    for (i = 0; i < t1.polylen; i++) {
        gen_matrix_row(&mat_row, i, tmp, 32);
        br_dilithium_third_party_polyvec_pointwise_acc_invmontgomery(&t1.vec[i], &mat_row, &s1);
        br_dilithium_third_party_poly_reduce(&t1.vec[i]);
        br_dilithium_third_party_poly_invntt_montgomery(&t1.vec[i]);
    }

    // Initialize s2
    for (i = 0; i < s2.polylen; i++) {
        br_dilithium_third_party_poly_uniform_eta(&s2.vec[i], tmp + 32, 32, nonce++, eta);
    }

    // Add error vector
    br_dilithium_third_party_polyvec_add(&t1, &t1, &s2);

    // Pack s2 into the secret key, allowing us to repurpose its underlying polynomial array
    br_dilithium_third_party_pack_sk(sk, NULL, &s2, NULL, mode);

    // Extract t1 and store public key
    br_dilithium_third_party_polyvec_freeze(&t1);
    br_dilithium_third_party_polyvec_power2round(&t1, &t0, &t1);
    if (pk) {
        br_dilithium_third_party_pack_pk(pk, &t1);
        memcpy(pk->rho, tmp, pk->rholen);
    } else {
        // Temporarly pack t1 into the t0 buffer of the secret key, 
        // to allow it to be used in the CRH computation (the t0 buffer is always larger than t1)
        for (i = 0; i < t1.polylen; ++i)
            br_dilithium_third_party_polyt1_pack(sk->t0 + i * 288, &t1.vec[i]);
        sk->t0len = t1.polylen * 288;
    }

    // Compute CRH(rho, t1) and store the secret key
    br_shake_init(&sc, 256);
    br_shake_inject(&sc, tmp, sk->rholen);

    if (pk) { // If there is no output public key, then the packed t1 is in t0
        br_shake_inject(&sc, pk->t1, pk->t1len);
    } else {
        br_shake_inject(&sc, sk->t0, sk->t0len);
    }
    br_shake_flip(&sc, 0);
    br_shake_produce(&sc, sk->tr, sk->trlen);

    br_dilithium_third_party_pack_sk(sk, NULL, NULL, &t0, mode);
    memcpy(sk->rho, tmp, sk->rholen);
    memcpy(sk->key, tmp + 64, sk->keylen);

#ifdef DILITHIUM_PRINT_KEYGEN
    printf("///////////// KEYGEN /////////////\n");
    // Print the full memory contents of the private and public key elements for manual comparison
    if(pk){
        printf("public key : rho (%ld bytes):\n", pk->rholen);
        print_hex_memory(pk->rho, pk->rholen);
        printf("public key : t1 (%ld bytes):\n", pk->t1len);
        print_hex_memory(pk->t1, pk->t1len);
    }

    printf("private key : rho (%ld bytes):\n", sk->rholen);
    print_hex_memory(sk->rho, sk->rholen);
    printf("private key : key (%ld bytes):\n", sk->keylen);
    print_hex_memory(sk->key, sk->keylen);
    printf("private key : tr (%ld bytes):\n", sk->trlen);
    print_hex_memory(sk->tr, sk->trlen);
    printf("private key : s1 (%ld bytes):\n", sk->s1len);
    print_hex_memory(sk->s1, sk->s1len);
    printf("private key : s2 (%ld bytes):\n", sk->s2len);
    print_hex_memory(sk->s2, sk->s2len);
    printf("private key : t0 (%ld bytes):\n", sk->t0len);
    print_hex_memory(sk->t0, sk->t0len);
	printf("/////////// KEYGEN END ///////////\n");
#endif

#ifdef DILITHIUM_TESTING_KEYGEN
	exit(-1);
#endif

    return 0;
}