#include "inner.h"
#include "liboqs/build/include/oqs/oqs.h"

uint32_t br_sphincs_p_third_party_keygen(br_sphincs_p_private_key *sk, void *kbuf_priv,
                                         br_sphincs_p_public_key *pk, void *kbuf_pub,
                                         unsigned mode) {

    // In case of null pk
    br_sphincs_p_public_key lpk;
	unsigned char lpk_buf[BR_SPHINCS_P_PUBLIC_BUFF_SIZE(SPHINCS_P_MAX_SIZE_MODE)];
    lpk.k = lpk_buf;
    lpk.klen = BR_SPHINCS_P_PUBLIC_BUFF_SIZE(mode);
    lpk.mode = mode;

    sk->k = kbuf_priv;
    sk->klen = BR_SPHINCS_P_SECRET_BUFF_SIZE(mode);
    sk->mode = mode;

    if(pk){    
        pk->k = kbuf_pub;
        pk->klen = BR_SPHINCS_P_PUBLIC_BUFF_SIZE(mode);
        pk->mode = mode;
    }

    br_sphincs_p_public_key* upk = (pk) ? pk : &lpk;
    // Third party keygen for Sphincs+
    // Switch over the mode to call the proper OQS keygen function

	OQS_STATUS rc;

    switch (mode) {
    case shake256_128f_robust:
        rc = OQS_SIG_sphincs_shake256_128f_robust_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_128f_simple:
        rc = OQS_SIG_sphincs_shake256_128f_simple_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_128s_robust:
        rc = OQS_SIG_sphincs_shake256_128s_robust_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_128s_simple:
        rc = OQS_SIG_sphincs_shake256_128s_simple_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_192f_robust:
        rc = OQS_SIG_sphincs_shake256_192f_robust_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_192f_simple:
        rc = OQS_SIG_sphincs_shake256_192f_simple_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_192s_robust:
        rc = OQS_SIG_sphincs_shake256_192s_robust_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_192s_simple:
        rc = OQS_SIG_sphincs_shake256_192s_simple_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_256f_robust:
        rc = OQS_SIG_sphincs_shake256_256f_robust_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_256f_simple:
        rc = OQS_SIG_sphincs_shake256_256f_simple_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_256s_robust:
        rc = OQS_SIG_sphincs_shake256_256s_robust_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_256s_simple:
        rc = OQS_SIG_sphincs_shake256_256s_simple_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case sha256_128f_robust:
        rc = OQS_SIG_sphincs_sha256_128f_robust_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case sha256_128f_simple:
        rc = OQS_SIG_sphincs_sha256_128f_simple_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case sha256_128s_robust:
        rc = OQS_SIG_sphincs_sha256_128s_robust_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case sha256_128s_simple:
        rc = OQS_SIG_sphincs_sha256_128s_simple_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case sha256_192f_robust:
        rc = OQS_SIG_sphincs_sha256_192f_robust_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case sha256_192f_simple:
        rc = OQS_SIG_sphincs_sha256_192f_simple_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case sha256_192s_robust:
        rc = OQS_SIG_sphincs_sha256_192s_robust_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case sha256_192s_simple:
        rc = OQS_SIG_sphincs_sha256_192s_simple_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case sha256_256f_robust:
        rc = OQS_SIG_sphincs_sha256_256f_robust_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case sha256_256f_simple:
        rc = OQS_SIG_sphincs_sha256_256f_simple_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case sha256_256s_robust:
        rc = OQS_SIG_sphincs_sha256_256s_robust_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case sha256_256s_simple:
        rc = OQS_SIG_sphincs_sha256_256s_simple_keypair(upk->k, sk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    default:
        break;
    }

    return 0;
}
