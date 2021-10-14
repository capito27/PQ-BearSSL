#include "inner.h"
#include "liboqs/build/include/oqs/oqs.h"


uint32_t br_sphincs_p_third_party_sign(const br_sphincs_p_private_key *sk,
                                       void *sig, size_t sig_max_len,
                                       const void *msg, size_t msg_len) {
    
    // Third party keygen for Sphincs+
    // Switch over the mode to call the proper OQS keygen function

	OQS_STATUS rc;
    size_t sig_len = 0;

    switch (sk->mode) {
    case shake256_128f_robust:
        rc = OQS_SIG_sphincs_shake256_128f_robust_sign(sig, &sig_len, msg, msg_len, sk->k);
        if (rc == OQS_SUCCESS) {
            return sig_len;
        }
        break;
    case shake256_128f_simple:
        rc = OQS_SIG_sphincs_shake256_128f_simple_sign(sig, &sig_len, msg, msg_len, sk->k);
        if (rc == OQS_SUCCESS) {
            return sig_len;
        }
        break;
    case shake256_128s_robust:
        rc = OQS_SIG_sphincs_shake256_128s_robust_sign(sig, &sig_len, msg, msg_len, sk->k);
        if (rc == OQS_SUCCESS) {
            return sig_len;
        }
        break;
    case shake256_128s_simple:
        rc = OQS_SIG_sphincs_shake256_128s_simple_sign(sig, &sig_len, msg, msg_len, sk->k);
        if (rc == OQS_SUCCESS) {
            return sig_len;
        }
        break;
    case shake256_192f_robust:
        rc = OQS_SIG_sphincs_shake256_192f_robust_sign(sig, &sig_len, msg, msg_len, sk->k);
        if (rc == OQS_SUCCESS) {
            return sig_len;
        }
        break;
    case shake256_192f_simple:
        rc = OQS_SIG_sphincs_shake256_192f_simple_sign(sig, &sig_len, msg, msg_len, sk->k);
        if (rc == OQS_SUCCESS) {
            return sig_len;
        }
        break;
    case shake256_192s_robust:
        rc = OQS_SIG_sphincs_shake256_192s_robust_sign(sig, &sig_len, msg, msg_len, sk->k);
        if (rc == OQS_SUCCESS) {
            return sig_len;
        }
        break;
    case shake256_192s_simple:
        rc = OQS_SIG_sphincs_shake256_192s_simple_sign(sig, &sig_len, msg, msg_len, sk->k);
        if (rc == OQS_SUCCESS) {
            return sig_len;
        }
        break;
    case shake256_256f_robust:
        rc = OQS_SIG_sphincs_shake256_256f_robust_sign(sig, &sig_len, msg, msg_len, sk->k);
        if (rc == OQS_SUCCESS) {
            return sig_len;
        }
        break;
    case shake256_256f_simple:
        rc = OQS_SIG_sphincs_shake256_256f_simple_sign(sig, &sig_len, msg, msg_len, sk->k);
        if (rc == OQS_SUCCESS) {
            return sig_len;
        }
        break;
    case shake256_256s_robust:
        rc = OQS_SIG_sphincs_shake256_256s_robust_sign(sig, &sig_len, msg, msg_len, sk->k);
        if (rc == OQS_SUCCESS) {
            return sig_len;
        }
        break;
    case shake256_256s_simple:
        rc = OQS_SIG_sphincs_shake256_256s_simple_sign(sig, &sig_len, msg, msg_len, sk->k);
        if (rc == OQS_SUCCESS) {
            return sig_len;
        }
        break;
    default:
        break;
    }

    return 0;
}
