#include "inner.h"

#include "ThirdParty/inc/kyber_poly.h"
#include "ThirdParty/inc/kyber_polyvec.h"
#include "ThirdParty/inc/kyber_cbd.h"

#ifdef KYBER_PRINT_DEC
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

// Macro to easily map contiguous buffer segments to a polyvec
#define polyarr_to_polyvec(dst, prev, size) dst.vec = prev.vec + prev.veclen; dst.veclen = size;

uint32_t br_kyber_third_party_decrypt(const br_kyber_private_key *sk,
                                      void *ss, size_t ss_len,
                                      const void *ct, size_t ct_len) {
    uint32_t eq = 1;
    unsigned int i;
    // 2 X buff, 2 X coins
    unsigned char tmp[4 * 32];
    // we MUST restrict the maximal value of count a fair bit if we don't want to explode our memory usage
    // Due to kyber1024 begin the maximum security standard, count will be limited to 4
    unsigned char cmp[BR_KYBER_CIPHERTEXT_SIZE(4)];
    br_shake_context sc;

    // We need at least 2 polyvect, of at least max count polynomials.
    br_kyber_third_party_poly temp[4 * 2];

    br_kyber_third_party_polyvec bp, priv;
    br_kyber_third_party_poly v, mp;
    br_kyber_public_key pk;

    if (ss_len != 32 || ct_len < BR_KYBER_CIPHERTEXT_SIZE(sk->polynbr)) {
        return 0;
    }

    priv.vec = temp;
    priv.veclen = sk->polynbr;
    polyarr_to_polyvec(bp, priv, sk->polynbr);

    pk.polyvec = sk->pubvec;
    pk.polyveclen = sk->pubveclen;
    pk.seed = sk->seed;
    pk.seedlen = sk->seedlen;
    pk.polynbr = sk->polynbr;

    // unpack the ciphertext + secret key
    br_kyber_third_party_polyvec_decompress(&bp, ct,  sk->polynbr);
    br_kyber_third_party_poly_decompress(&v, ct + ct_len - (sk->polynbr + 1) * 32,  sk->polynbr);
    br_kyber_third_party_polyvec_frombytes(&priv, sk->privec);

    // Recover the encapsulated polynomial
    br_kyber_third_party_polyvec_ntt(&bp);
    br_kyber_third_party_polyvec_pointwise_acc_montgomery(&mp, &priv, &bp);
    br_kyber_third_party_poly_invntt_tomont(&mp);

    br_kyber_third_party_poly_sub(&mp, &v, &mp);
    br_kyber_third_party_poly_reduce(&mp);

    // Recover the pre-k secret
    br_kyber_third_party_poly_tomsg(tmp, &mp);

    /* Multitarget countermeasure for coins + contributory KEM */
    br_shake_init(&sc, 512);
    br_shake_inject(&sc, tmp, 32);
    br_shake_inject(&sc, sk->hpk, sk->hpklen);
    br_shake_flip(&sc, 1);
    br_shake_produce(&sc, tmp + 64, 64);


    // Try to encrypt the clear message, to check it's valid
    br_kyber_third_party_encrypt(NULL, &pk, cmp,
                                 BR_KYBER_CIPHERTEXT_SIZE(sk->polynbr),
                                 tmp, 32 * 4);

    // Constant time equality check
    for (i = 0; i < BR_KYBER_CIPHERTEXT_SIZE(sk->polynbr) / 4; i++) {
        eq &= EQ(*((uint32_t * )(cmp + 4 * i)), *((uint32_t * )(ct + 4 * i)));
    }

    // Overwrite coins with hash of ciphertext
    br_shake_init(&sc, 256);
    br_shake_inject(&sc, ct, BR_KYBER_CIPHERTEXT_SIZE(sk->polynbr));
    br_shake_flip(&sc, 1);
    br_shake_produce(&sc, tmp + 3 * 32, 32);

    // Overwrite pre-k with z only if not equal
    CCOPY(!eq, tmp + 64, sk->z, sk->zlen);

    // Export shared secret
    br_shake_init(&sc, 256);
    br_shake_inject(&sc, tmp + 64, 64);
    br_shake_flip(&sc, 0);
    br_shake_produce(&sc, ss, 32);

#ifdef KYBER_PRINT_DEC
    printf("////////////// DEC ///////////////\n");
    // Print the full memory contents of the extracted shared secret
    printf("Equality : %s\n", (eq? "Equal": "Not Equal"));
    printf("shared secret (DEC) (%d bytes):\n", 32);
    print_hex_memory(ss, 32);
    printf("//////////// END DEC /////////////\n");
#endif

#ifdef KYBER_TESTING_DEC
    exit(-1);
#endif
    return 1;
}