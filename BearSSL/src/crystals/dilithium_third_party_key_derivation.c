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

// Valid calculation for security levels 1 through 4
#define polyeta_packed(mode) ((mode) <= 3 ? 128 : 96)

// Macro to easily map contiguous buffer segments to a key section
#define buff_to_key(dst, src, size) dst = src; dst##len = size; src += dst##len;

// Macro to easily map contiguous buffer segments to a polyvec
#define polyarr_to_polyvec(dst, prev, size) dst.vec = prev.vec + prev.polylen; dst.polylen = size;

uint32_t br_dilithium_third_party_public_key_derivate(
                                                      const br_dilithium_private_key *sk, 
                                                      br_dilithium_public_key *pk, void *kbuf_pub) {
    unsigned int i;

    // We need at least 3 polyvect, of at least "mode+2" polynomials.
    // Thus, we MUST restrict the maximal value of count a fair bit
    // Due to Dilithium4 being the maximum security standard, mode will be limited to 4,
    // thus 2 polyvec of 6 elements and one of 5 elements
    br_dilithium_third_party_poly temp[2 * 6 + 5];
    br_dilithium_third_party_polyvec s1, s2, t1, t0, mat_row;
    

    // Map the public buffers to the respective key regions
    buff_to_key(pk->rho, kbuf_pub, 32);
    buff_to_key(pk->t1, kbuf_pub, (sk->mode + 2) * 288);
    pk->mode = sk->mode;

    // Map the local polynomial vectors to the temporary poly buffer
    s1.vec = temp;
    s1.polylen = sk->mode + 1;

    polyarr_to_polyvec(t1, s1, sk->mode + 2);
    // make t0, s1 and mat_row share their underlying poly array, 
    // due to there being no overlap on their usage
    polyarr_to_polyvec(t0, t1, sk->mode + 2);
    polyarr_to_polyvec(mat_row, t1, sk->mode + 1);
    polyarr_to_polyvec(s2, t1, sk->mode + 2);

    // Load s1
    br_dilithium_third_party_unpack_sk(&s1, NULL, NULL, sk);

    // Matrix-vector multiplication
    br_dilithium_third_party_polyvec_ntt(&s1);
    for (i = 0; i < t1.polylen; i++) {
        gen_matrix_row(&mat_row, i, sk->rho, sk->rholen);
        br_dilithium_third_party_polyvec_pointwise_acc_invmontgomery(&t1.vec[i], &mat_row, &s1);
        br_dilithium_third_party_poly_reduce(&t1.vec[i]);
        br_dilithium_third_party_poly_invntt_montgomery(&t1.vec[i]);
    }

    // Load s2
    br_dilithium_third_party_unpack_sk(NULL, &s2, NULL, sk);

    // Add error vector
    br_dilithium_third_party_polyvec_add(&t1, &t1, &s2);

    // Extract t1 and store public key
    br_dilithium_third_party_polyvec_freeze(&t1);
    br_dilithium_third_party_polyvec_power2round(&t1, &t0, &t1);
    br_dilithium_third_party_pack_pk(pk, &t1);
    memcpy(pk->rho, sk->rho, sk->rholen);

    return 0;
}