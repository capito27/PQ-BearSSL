#include "inner.h"
#include "liboqs/build/include/oqs/oqs.h"

uint32_t br_sphincs_p_third_party_vrfy(const br_sphincs_p_public_key *pk,
                                         const void *msg, size_t msg_len,
                                         const void *sig, size_t sig_len) {

    // Third party keygen for Sphincs+
    // Switch over the mode to call the proper OQS keygen function

	OQS_STATUS rc;

    switch (pk->mode) {
    case shake256_128f_robust:
        rc = OQS_SIG_sphincs_shake256_128f_robust_verify(msg, msg_len, sig, sig_len, pk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_128f_simple:
        rc = OQS_SIG_sphincs_shake256_128f_simple_verify(msg, msg_len, sig, sig_len, pk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_128s_robust:
        rc = OQS_SIG_sphincs_shake256_128s_robust_verify(msg, msg_len, sig, sig_len, pk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_128s_simple:
        rc = OQS_SIG_sphincs_shake256_128s_simple_verify(msg, msg_len, sig, sig_len, pk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_192f_robust:
        rc = OQS_SIG_sphincs_shake256_192f_robust_verify(msg, msg_len, sig, sig_len, pk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_192f_simple:
        rc = OQS_SIG_sphincs_shake256_192f_simple_verify(msg, msg_len, sig, sig_len, pk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_192s_robust:
        rc = OQS_SIG_sphincs_shake256_192s_robust_verify(msg, msg_len, sig, sig_len, pk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_192s_simple:
        rc = OQS_SIG_sphincs_shake256_192s_simple_verify(msg, msg_len, sig, sig_len, pk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_256f_robust:
        rc = OQS_SIG_sphincs_shake256_256f_robust_verify(msg, msg_len, sig, sig_len, pk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_256f_simple:
        rc = OQS_SIG_sphincs_shake256_256f_simple_verify(msg, msg_len, sig, sig_len, pk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_256s_robust:
        rc = OQS_SIG_sphincs_shake256_256s_robust_verify(msg, msg_len, sig, sig_len, pk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    case shake256_256s_simple:
        rc = OQS_SIG_sphincs_shake256_256s_simple_verify(msg, msg_len, sig, sig_len, pk->k);
        if (rc == OQS_SUCCESS) {
            return 1;
        }
        break;
    default:
        break;
    }

    return 0;
}