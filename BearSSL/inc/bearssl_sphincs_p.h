#ifndef BR_BEARSSL_SPHINCS_P_H__
#define BR_BEARSSL_SPHINCS_P_H__

#include <stddef.h>
#include <stdint.h>

#include "bearssl_hash.h"
#include "bearssl_rand.h"

#ifdef __cplusplus
extern "C" {
#endif
/** \file bearssl_sphincs_p.h
 *
 * # SPHINCS+
 *
 * This file documents the SPHINCS+ implementation.
 *
 */


/**
 * \brief SPHINCS+ public key.
 *
 */
typedef struct {
    /** \brief key material */
    unsigned char *k;
    /** \brief key material length (in bytes) */
    size_t klen;
    /** \brief SPHINCS+ mode */
    uint8_t mode;
} br_sphincs_p_public_key;

/**
 * \brief SPHINCS+ private key.
 *
 * The structure matches the canonical private key representation order.
 */
typedef struct {
    /** \brief key material */
    unsigned char *k;
    /** \brief key material length (in bytes) */
    size_t klen;
    /** \brief SPHINCS+ mode */
    uint8_t mode;
} br_sphincs_p_private_key;

/**
 * \brief Type for a SPHINCS+ signature engine.
 *
 * Parameters are:
 *
 *   - The secret key.
 *
 *   - The message to sign. Its length (in bytes) is provided.
 *
 *   - The signature buffer. Its maximum length (in bytes) is provided;
 *     if that length is lower than the minimal signature size for the secret key
 *     type + the message length, then an error is reported.
 *
 * The signature buffer (`sig`, length `sig_max_len`) may NOT overlap with the
 * message buffer (`msg`, length `msg_len`).
 *
 * This function returns the actual signature length, in bytes;
 * on error, zero is returned. An error is reported if the output buffer
 * is not large enough, or the secret key is invalid.
 *
 * on error, sig will be undetermined
 *
 * \param sk           SPHINCS+ private key.
 * \param sig          destination buffer.
 * \param sig_max_len  destination buffer length (maximum signature size).
 * \param msg          message to sign.
 * \param msg_len      source message length (in bytes).
 * \return signature length (in bytes), or 0 on error.
 */
typedef uint32_t (*br_sphincs_p_sign)(const br_sphincs_p_private_key *sk,
                                      void *sig, size_t sig_max_len,
                                      const void *msg, size_t msg_len);

/**
 * \brief Type for a SPHINCS+ signature verification engine.
 *
 * Parameters are:
 *
 *   - The public key.
 *
 *   - The message output buffer. Its maximum length (in bytes) is provided;
 *     if that length is lower than the message size, then an error is reported.
 *
 *   - The signature buffer. Its length (in bytes) is provided;
 *     if that length is lower than the minimal signature size for a key
 *     type, then an error is reported.
 *
 * The message output buffer (`msg`, length `msg_max_len`) may NOT overlap with the
 * signature buffer (`sig`, length `sig_max_len`).
 *
 * on error, zero is returned. An error is reported if the signature buffer is
 * not large enough, or verification failed.
 *
 * \param pk            SPHINCS+ public key.
 * \param msg           destination message buffer
 * \param msg_len       destination message buffer max length (in bytes).
 * \param sig           signature buffer.
 * \param sig_len       signature length (in bytes).
 * \return 1 on success, 0 on error.
 */
typedef uint32_t (*br_sphincs_p_vrfy)(const br_sphincs_p_public_key *pk,
                                        const void *msg, size_t msg_len,
                                        const void *sig, size_t sig_len);

/**
 * \brief SPHINCS+ signature with the "third party" engine.
 *
 * \see br_sphincs_p_sign
 *
 * \param sk           SPHINCS+ private key.
 * \param sig          destination buffer.
 * \param sig_max_len  destination buffer length (maximum signature size).
 * \param msg          message to sign.
 * \param msg_len      source message length (in bytes).
 * \return signature length (in bytes), or 0 on error.
 */
uint32_t br_sphincs_p_third_party_sign(const br_sphincs_p_private_key *sk,
                                       void *sig, size_t sig_max_len,
                                       const void *msg, size_t msg_len);

/**
 * \brief SPHINCS+ signature verification with the "third party" engine.
 *
 * \see br_sphincs_p_vrfy
 *
 * \param pk            SPHINCS+ public key.
 * \param msg           destination message buffer
 * \param msg_len       destination message buffer max length (in bytes).
 * \param sig           signature buffer.
 * \param sig_len       signature length (in bytes).
 * \return 1 on success, 0 on error.
 */
uint32_t br_sphincs_p_third_party_vrfy(const br_sphincs_p_public_key *pk,
                                         const void *msg, size_t msg_len,
                                         const void *sig, size_t sig_len);

/**
 * \brief Get "default" SPHINCS+ implementation (signature engine).
 *
 * This returns the preferred implementation of SPHINCS+ (signature engine)
 * on the current system.
 *
 * \return  the default implementation.
 */
br_sphincs_p_sign br_sphincs_p_sign_get_default(void);

/**
 * \brief Get "default" SPHINCS+ implementation (signature verification).
 *
 * This returns the preferred implementation of SPHINCS+ (signature verification)
 * on the current system.
 *
 * \return  the default implementation.
 */
br_sphincs_p_vrfy br_sphincs_p_vrfy_get_default(void);


/**
 * \brief SPHINCS+ operation modes
 */
#define shake256_128f_robust 0 
#define shake256_128f_simple 1
#define shake256_128s_robust 2
#define shake256_128s_simple 3

#define shake256_192f_robust 4 
#define shake256_192f_simple 5
#define shake256_192s_robust 6
#define shake256_192s_simple 7

#define shake256_256f_robust 8 
#define shake256_256f_simple 9
#define shake256_256s_robust 10
#define shake256_256s_simple 11

/**
 * \brief SPHINCS+ largest operating modes
 */
#define SPHINCS_P_MAX_SIZE_MODE shake256_256f_robust
/**
 * \brief Get buffer size to hold a SPHINCS+ public key.
 *
 * This macro returns the length (in bytes) of the buffer needed to
 * receive a public key, as generated by one of the `br_sphincs_p_*_keygen()`
 * functions. If the provided mode is a constant expression, then the whole
 * macro evaluates to a constant expression.
 *
 * \param mode   target SPHINCS+ operation mode, guaranteed valid from 0 to 11 (included)
 * \return  the length of the public key polynomial vector buffer, in bytes.
 */
#define BR_SPHINCS_P_PUBLIC_BUFF_SIZE(mode)     ((((mode) / 4) + 2) * 16)

/**
 * \brief Get buffer size to hold a SPHINCS+ secret key.
 *
 * This macro returns the length (in bytes) of the buffer needed to
 * receive all secret key polynomial vectors, as generated by one of
 * the `br_sphincs_p_*_keygen()` functions. If the provided mode is a constant
 * expression, then the whole macro evaluates to a constant expression.
 *
 * \param mode   target SPHINCS+ operation mode,  guaranteed valid from 0 to 11 (included)
 * \return  the length of the private key polynomial vector buffer, in bytes.
 */
#define BR_SPHINCS_P_SECRET_BUFF_SIZE(mode)   ((((mode) / 4) + 2) * 32)

/**
 * \brief Get the buffer size to hold SPHINCS+ signatures
 *
 * This macro returns the size that a given signature would take, for a given
 * SPHINCS+ operation mode, as used by one of the `br_sphincs_p_*_sign()`
 * or `br_sphincs_p_*verify()` * functions. If the provided mode is a
 * constant expression, then the whole macro evaluates to a constant expression.
 *
 * \param mode      SPHINCS+ operation mode, guaranteed valid from 0 to 11 (included)
 * \return the length of buffer able to hold the signature.
 */
#define BR_SPHINCS_P_SIGNATURE_SIZE(mode)   ((size_t)( \
    (((mode) / 2) == 0) ? 17088 : ( \
    (((mode) / 2) == 1) ?  7856 : ( \
    (((mode) / 2) == 2) ? 35664 : ( \
    (((mode) / 2) == 3) ? 16224 : ( \
    (((mode) / 2) == 4) ? 49856 : ( \
    (((mode) / 2) == 5) ? 29792 : ( \
    -1))))))))

/**
 * \brief Type for SPHINCS+ key pair generator implementation.
 *
 * This function generates a new SPHINCS+ with `mode` operation mode.
 * The private key elements are written in the `kbuf_priv` buffer,
 * and pointer values and length fields to these elements are populated
 * in the provided private key structure `sk`. Similarly, the public key
 * elements are written in `kbuf_pub`, with pointers and lengths set in `pk`.
 *
 * If `pk` is `NULL`, then `kbuf_pub` may be `NULL`, and only the
 * private key is set.
 *
 * Only `mode` values of 1, 2, 3 and 4 have been tested and validated to work
 * 
 *
 * Returned value is 1 on success, 0 on error. An error is reported
 * if the requested mode is outside of the supported key sizes.
 *
 * \param sk          SPHINCS+ private key structure (destination)
 * \param kbuf_priv   buffer for private key elements
 * \param pk          SPHINCS+ public key structure (destination), or `NULL`
 * \param kbuf_pub    buffer for public key elements, or `NULL`
 * \param mode        target operation mode.
 * \return  1 on success, 0 on error (invalid parameters)
 */
typedef uint32_t (*br_sphincs_p_keygen)(br_sphincs_p_private_key *sk, void *kbuf_priv,
                                        br_sphincs_p_public_key *pk, void *kbuf_pub,
                                        unsigned mode);

/**
 * \brief SPHINCS+ key pair generation with the "third_party" engine.
 *
 * \see br_sphincs_p_keygen
 *
 * \param sk          SPHINCS+ private key structure (destination)
 * \param kbuf_priv   buffer for private key elements
 * \param pk          SPHINCS+ public key structure (destination), or `NULL`
 * \param kbuf_pub    buffer for public key elements, or `NULL`
 * \param mode        target operation mode.
 * \return  1 on success, 0 on error (invalid parameters)
 */
uint32_t br_sphincs_p_third_party_keygen(br_sphincs_p_private_key *sk, void *kbuf_priv,
                                         br_sphincs_p_public_key *pk, void *kbuf_pub,
                                         unsigned mode);

/**
 * \brief Get "default" SPHINCS+ implementation (key pair generation).
 *
 * This returns the preferred implementation of SPHINCS+ (key pair generation)
 * on the current system.
 *
 * \return  the default implementation.
 */
br_sphincs_p_keygen br_sphincs_p_keygen_get_default(void);



#ifdef __cplusplus
}
#endif

#endif
