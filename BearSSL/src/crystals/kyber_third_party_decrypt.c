#include "inner.h"
#include "ThirdParty/inc/tiny_sha3.h"
#include "ThirdParty/inc/common_poly.h"
#include "ThirdParty/inc/common_polyvec.h"
#include "ThirdParty/inc/kyber_cbd.h"

uint32_t
br_kyber_third_party_decrypt(const br_kyber_private_key *sk,
                             void *ss, size_t ss_max_len,
                             const void *ct, size_t ct_max_len) {
    uint32_t eq = 1;
    unsigned int i;
    // 2 X buff, 2 X coins
    unsigned char tmp[4 * 32];
    // we MUST restrict the maximal value of count a fair bit if we don't want to explode our memory usage
    // Due to kyber1024 begin the maximum security standard, count will be limited to 4
    unsigned char cmp[BR_KYBER_CIPHERTEXT_SIZE(4)];
    sha3_ctx_t sha3ctx;
    br_shake_context sc;

    // We need at least 5 polyvect, of at least max count polynomials.
    poly temp[4 * 2];

    polyvec bp, priv;
    poly v, mp;

    if (ss_max_len < 32 || ct_max_len < BR_KYBER_CIPHERTEXT_SIZE(BR_KYBER_POLYVEC_COUNT(sk->polyveclen))) {
        printf("maxlen : %d\n", ss_max_len);
        return -1;
    }

    priv.vec = temp;
    priv.veclen = BR_KYBER_POLYVEC_COUNT(sk->polyveclen);
    bp.vec = temp + 4;
    bp.veclen = BR_KYBER_POLYVEC_COUNT(sk->polyveclen);


    // unpack the ciphertext + secret key
    polyvec_decompress(&bp, ct, BR_KYBER_CIPHERTEXT_SIZE(bp.veclen) - ((bp.veclen + 1) * 32));
    poly_decompress(&v, ct + BR_KYBER_CIPHERTEXT_SIZE(bp.veclen) - ((bp.veclen + 1) * 32), ((bp.veclen + 1) * 32));
    polyvec_frombytes(&priv, sk->polyvec, sk->polyveclen);


    // Recover the encapsulated polynome
    polyvec_ntt(&bp);
    polyvec_pointwise_acc_montgomery(&mp, &priv, &bp);
    poly_invntt_tomont(&mp);

    poly_sub(&mp, &v, &mp);
    poly_reduce(&mp);

    // Recover the pre-k secret
    poly_tomsg(tmp, 32, &mp);

    /* Multitarget countermeasure for coins + contributory KEM */
    sha3_init(&sha3ctx, 64);
    sha3_update(&sha3ctx, tmp, 32);
    sha3_update(&sha3ctx, sk->hpk, sizeof(sk->hpk));
    sha3_final(tmp + 64, &sha3ctx);

    // Try to encrypt the clear message, to check it's valid
    br_kyber_third_party_encrypt(NULL, sk->pubkey, cmp,
                                 BR_KYBER_CIPHERTEXT_SIZE(BR_KYBER_POLYVEC_COUNT(sk->polyveclen)),
                                 tmp, 32 * 4);

    // Constant time equality check
    for (i = 0; i < BR_KYBER_CIPHERTEXT_SIZE(BR_KYBER_POLYVEC_COUNT(sk->polyveclen)); i += 4) {
        eq = EQ(eq, EQ(*((uint32_t * )(cmp + 4 * i)), *((uint32_t * )(ct + 4 * i))));
    }

    // overwrite coins with hash of ciphertext
    sha3(ct, BR_KYBER_CIPHERTEXT_SIZE(bp.veclen), tmp + 3 * 32, 32);

    CCOPY(eq, tmp + 64, sk->z, sizeof(sk->z));

    br_shake_init(&sc, 256);
    br_shake_inject(&sc, tmp + 64, 64);
    br_shake_flip(&sc);
    br_shake_produce(&sc, ss, 32);

#ifdef TESTING_DEC
    // Print the full memory contents of the private and public key
    printf("Equality : %s\n", (eq? "Not Equal": "Equal"));
    printf("shared secret (DEC) (%d bytes):\n", 32);
    dec_print_hex_memory(ss, 32);

    exit(-1);
}

void dec_print_hex_memory(void *mem, size_t length) {
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