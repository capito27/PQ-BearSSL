#ifndef BR_BEARSSL_DILITHIUM_H__
#define BR_BEARSSL_DILITHIUM_H__

#include <stddef.h>
#include <stdint.h>

#include "bearssl_hash.h"
#include "bearssl_rand.h"

#ifdef __cplusplus
extern "C" {
#endif
//TODO UPDATE DESCRIPTION
/** \file bearssl_dilithium.h
 *
 * # Dilithium
 *
 * This file documents the Crystals-Dilithium implementation.
 *
 * ## Key Elements
 *
 * Dilithium public keys consist of a vector of polynomials of degree 255,
 * as well a seed to generate a pseudo-random rectangular polynomial matrix.
 *
 * Dilithium private keys contain a copy of the public key for convenience, as well as
 * two secret vectors sampled upon the pseudo-random matrix, a secret key
 *
 * Such seeds are represented with a 32-byte unsigned char buffer.
 *
 * Such polynomials are represented with a buffer of 256 N-bit integers.
 *
 * This implementation has been tested to support Dilithium modes one through four
 *
 * Such integers are stored compressed in big-endian two's complement notation:
 * first byte is the least significant, and the value may be negative (the
 * "sign bit" being the first bit of the most significant byte).
 *
 *
 * Public key structures thus contain, a pointer to the coefficient
 * byte of smallest degree of the first compressed
 * polynomial (`unsigned uint16_t *`), a length (`size_t`) which
 * is the number of relevant bytes and a pointer (`unsigned char *`) to the seed.
 *
 * Private key structures thus contain a pointer to the coefficient
 * byte of smallest degree of the first compressed polynomial (`unsigned uint16_t *`),
 * a length (`size_t`) which is the number of relevant bytes,.
 * a pointer to a public key structure, a pointer to the the intermediary
 * hash (`unsigned char *`) as well as a pointer to the pseudo-random failure value.
 */

/**
 * \brief Temporary flag to enable testing framework, to verify correctness of crypto.
 */

// These define will stop the program after their specific function as well as force the RNG output to the define below
//#define DILITHIUM_TESTING_KEYGEN
//#define DILITHIUM_TESTING_SIGN
//#define DILITHIUM_TESTING_VERIFY

// This define sets the RNG to always simulate the return of the following byte (only when used with the testing macros)
#define DILITHIUM_RNG_OUTPUT_FORCE 0x33

// These define will print the contents of the relevant data
//#define DILITHIUM_PRINT_KEYGEN
//#define DILITHIUM_PRINT_SIGN
//#define DILITHIUM_PRINT_VERIFY

/**
 * \brief Flag that enables faster signing (roughly 25% faster) at the cost of doubling memory usage during
 *        the signature generation
 */
#define BR_DILITHIUM_FAST_SIGN

/**
 * \brief Kyber public key.
 *
 * The structure matches the canonical public key representation order.
 */
typedef struct {
    /** \brief rho matrix seed */
    unsigned char *rho;
    /** \brief seed length (in bytes) */
    size_t rholen;
    /** \brief packed polynomial vector. */
    unsigned char *t1;
    /** \brief vector length (in bytes). */
    size_t t1len;
    /** \brief Dilithium security mode */
    uint8_t mode;
} br_dilithium_public_key;

/**
 * \brief Kyber private key.
 *
 * The structure matches the canonical private key representation order.
 */
typedef struct {
    /** \brief rho matrix seed */
    unsigned char *rho;
    /** \brief seed length (in bytes). */
    size_t rholen;
    /** \brief key */
    unsigned char *key;
    /** \brief key length (in bytes). */
    size_t keylen;
    /** \brief collision resistant hash */
    unsigned char *tr;
    /** \brief hash length (in bytes). */
    size_t trlen;
    /** \brief packed secret polynomial vector. */
    unsigned char *s1;
    /** \brief vector length (in bytes). */
    size_t s1len;
    /** \brief packed noise polynomial vector. */
    unsigned char *s2;
    /** \brief vector length (in bytes). */
    size_t s2len;
    /** \brief packed polynomial vector. */
    unsigned char *t0;
    /** \brief vector length (in bytes). */
    size_t t0len;
    /** \brief Dilithium security mode */
    uint8_t mode;
} br_dilithium_private_key;

/**
 * \brief Type for a Dilithium signature engine.
 *
 * Parameters are:
 *
 *   - A source of random bytes. The source must be already initialized.
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
 * \param rnd          source of random bytes.
 * \param sk           Dilithium public key.
 * \param sig          destination buffer.
 * \param sig_max_len  destination buffer length (maximum signature size).
 * \param msg          message to sign.
 * \param msg_len      source message length (in bytes).
 * \return signature length (in bytes), or 0 on error.
 */
typedef uint32_t (*br_dilithium_sign)(const br_prng_class **rnd,
                                      const br_dilithium_private_key *sk,
                                      void *sig, size_t sig_max_len,
                                      const void *msg, size_t msg_len);

/**
 * \brief Type for a Dilithium signature verification engine.
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
 * \param pk            Dilithium public key.
 * \param msg           destination message buffer
 * \param msg_len       destination message buffer max length (in bytes).
 * \param sig           signature buffer.
 * \param sig_len       signature length (in bytes).
 * \return 1 on success, 0 on error.
 */
typedef uint32_t (*br_dilithium_vrfy)(const br_dilithium_public_key *pk,
                                        const void *msg, size_t msg_len,
                                        const void *sig, size_t sig_len);

/**
 * \brief Dilithium signature with the "third party" engine.
 *
 * \see br_dilithium_sign
 *
 * \param rnd          source of random bytes.
 * \param sk           Dilithium public key.
 * \param sig          destination buffer.
 * \param sig_max_len  destination buffer length (maximum signature size).
 * \param msg          message to sign.
 * \param msg_len      source message length (in bytes).
 * \return signature length (in bytes), or 0 on error.
 */
uint32_t br_dilithium_third_party_sign(const br_prng_class **rnd,
                                       const br_dilithium_private_key *sk,
                                       void *sig, size_t sig_max_len,
                                       const void *msg, size_t msg_len);

/**
 * \brief Dilithium signature verification with the "third party" engine.
 *
 * \see br_dilithium_vrfy
 *
 * \param pk            Dilithium public key.
 * \param msg           destination message buffer
 * \param msg_len       destination message buffer max length (in bytes).
 * \param sig           signature buffer.
 * \param sig_len       signature length (in bytes).
 * \return 1 on success, 0 on error.
 */
uint32_t br_dilithium_third_party_vrfy(const br_dilithium_public_key *pk,
                                         const void *msg, size_t msg_len,
                                         const void *sig, size_t sig_len);

/**
 * \brief Get "default" Dilithium implementation (signature engine).
 *
 * This returns the preferred implementation of Dilithium (signature engine)
 * on the current system.
 *
 * \return  the default implementation.
 */
br_dilithium_sign br_dilithium_sign_get_default(void);

/**
 * \brief Get "default" Dilithium implementation (signature verification).
 *
 * This returns the preferred implementation of Dilithium (signature verification)
 * on the current system.
 *
 * \return  the default implementation.
 */
br_dilithium_vrfy br_dilithium_vrfy_get_default(void);


/**
 * \brief Get maximal supported Dilithium security mode
 */
#define BR_DILITHIUM_MAX_SECURITY_MODE 4

/**
 * \brief Get buffer size to hold a Dilithium public key.
 *
 * This macro returns the length (in bytes) of the buffer needed to
 * receive a public key, as generated by one of the `br_dilithium_*_keygen()`
 * functions. If the provided mode is a constant expression, then the whole
 * macro evaluates to a constant expression.
 *
 * \param mode   target Dilithium security mode, guaranteed valid from 1 to 4 (included)
 * \return  the length of the public key polynomial vector buffer, in bytes.
 */
#define BR_DILITHIUM_PUBLIC_BUFF_SIZE(mode)     (288u * ((mode) + 2u) + 32u)

/**
 * \brief Get buffer size to hold a Dilithium secret key.
 *
 * This macro returns the length (in bytes) of the buffer needed to
 * receive all secret key polynomial vectors, as generated by one of
 * the `br_dilithium_*_keygen()` functions. If the provided mode is a constant
 * expression, then the whole macro evaluates to a constant expression.
 *
 * \param mode   target Dilithium security mode, guaranteed valid from 1 to 4 (included)
 * \return  the length of the private key polynomial vector buffer, in bytes.
 */
#define BR_DILITHIUM_SECRET_BUFF_SIZE(mode)   (((mode) + 2u) * 448u + \
                                               (2u * (mode) + 3u) * ((mode) <= 3u ? 128u : 96u) + 2u * 32u + 48u)

/**
 * \brief Get the Dilithium security mode from a public key buffer size
 *
 * This macro returns the Dilithium security of a public key according to
 * its size, as used by one of the `br_dilithium_*_verify()` functions.
 *
 * \param pk pointer to public key to get security mode of
 * \return  security mode, guaranteed valid from 1 to 4 (included)
 */
#define BR_DILITHIUM_PUBLIC_KEY_MODE(size)   (((size) - 32u) / 288u - 2u)

/**
 * \brief Get the Dilithium security mode from a private key size
 *
 * This macro returns the Dilithium security of a private key according to
 * its size, as used by one of the `br_dilithium_*_sign()` functions.
 *
 * \param pk pointer to private key to get security mode of
 * \return   security mode, guaranteed valid for results from 1 to 4 (included)
 */
#define BR_DILITHIUM_SECRET_KEY_MODE(size)   ((size) < 3856u ? ((size) + 16u) / 704u - 2u : ((size) + 368u) / 704u - 2u)

/**
 * \brief Get the buffer size to hold Dilithium signatures
 *
 * This macro returns the size that a given signature would take, for a given
 * Dilithium security mode, as used by one of the `br_dilithium_*_sign()`
 * or `br_dilithium_*verify()` * functions. If the provided mode is a
 * constant expression, then the whole macro evaluates to a constant expression.
 *
 * \param mode      Dilithium security mode
 * \return the length of buffer able to hold the signature.
 */
#define BR_DILITHIUM_SIGNATURE_SIZE(mode)    (((mode) + 1u) * 640u + ((mode) <= 3u ? (mode) * 16u + 48u : 120u) + \
                                             ((mode) + 2u) + 32u + 8u )

/**
 * \brief Type for Kyber key pair generator implementation.
 *
 * This function generates a new Dilithium with `mode` security mode.
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
 * The provided PRNG (`rng_ctx`) must have already been initialized
 * and seeded.
 *
 * Returned value is 1 on success, 0 on error. An error is reported
 * if the requested mode is outside of the supported key sizes.
 *
 * \param rng_ctx     source PRNG context (already initialized)
 * \param sk          Dilithium private key structure (destination)
 * \param kbuf_priv   buffer for private key elements
 * \param pk          Dilithium public key structure (destination), or `NULL`
 * \param kbuf_pub    buffer for public key elements, or `NULL`
 * \param mode        target security mode.
 * \return  1 on success, 0 on error (invalid parameters)
 */
typedef uint32_t (*br_dilithium_keygen)(const br_prng_class **rng_ctx,
                                        br_dilithium_private_key *sk, void *kbuf_priv,
                                        br_dilithium_public_key *pk, void *kbuf_pub,
                                        unsigned mode);

/**
 * \brief Dilithium key pair generation with the "third_party" engine.
 *
 * \see br_dilithium_keygen
 *
 * \param rng_ctx     source PRNG context (already initialized)
 * \param sk          Dilithium private key structure (destination)
 * \param kbuf_priv   buffer for private key elements
 * \param pk          Dilithium public key structure (destination), or `NULL`
 * \param kbuf_pub    buffer for public key elements, or `NULL`
 * \param mode        target security mode.
 * \return  1 on success, 0 on error (invalid parameters)
 */
uint32_t br_dilithium_third_party_keygen(const br_prng_class **rng_ctx,
                                         br_dilithium_private_key *sk, void *kbuf_priv,
                                         br_dilithium_public_key *pk, void *kbuf_pub,
                                         unsigned mode);

/**
 * \brief Get "default" Dilithium implementation (key pair generation).
 *
 * This returns the preferred implementation of Dilithium (key pair generation)
 * on the current system.
 *
 * \return  the default implementation.
 */
br_dilithium_keygen br_dilithium_keygen_get_default(void);

/**
 * \brief Type for Kyber public key derivation implementation.
 *
 * This function derivates the associated public key to a given private key.
 * The public key elements are written in `kbuf_pub`, 
 * with pointers and lengths set in `pk`.
 * 
 * The given buffer MUST be large enough to hold the derivated public key
 *
 * Returned value is 1 on success, 0 on error.
 *
 * \param sk          Dilithium private key structure (source)
 * \param pk          Dilithium public key structure (destination)
 * \param kbuf_pub    buffer for public key elements
 * \return  1 on success, 0 on error (invalid parameters)
 */
typedef uint32_t (*br_dilithium_public_key_derivate)(
    const br_dilithium_private_key *sk,
    br_dilithium_public_key *pk, void *kbuf_pub);

/**
 * \brief Kyber public key derivation with the "third_party" engine.
 *
 * \see br_dilithium_public_key_derivate
 *
 * \param sk          Dilithium private key structure (source)
 * \param pk          Dilithium public key structure (destination)
 * \param kbuf_pub    buffer for public key elements
 * \return  1 on success, 0 on error (invalid parameters)
 */
uint32_t br_dilithium_third_party_public_key_derivate(
    const br_dilithium_private_key *sk, 
    br_dilithium_public_key *pk, void *kbuf_pub);

/**
 * \brief Get "default" Dilithium implementation (public key derivation).
 *
 * This returns the preferred implementation of Dilithium (public key derivation)
 * on the current system.
 *
 * \return  the default implementation.
 */
br_dilithium_public_key_derivate br_dilithium_public_key_derivate_get_default(void);


/**
 * \brief Helper function to load a dilithium private key from an associated buffer
 * 
 * This function will NOT copy any material from the key buffer, as such, 
 * the key buffer MUST remain valid as long as its associated private key structure
 *
 * \param kbuf       Dilithium private key buffer containing the private key material
 * \param kbuf_len   Dilithium private key buffer length
 * \param sk         Dilithium private key structure (destination)
 */
void br_dilithium_keygen_load_private_key(void *kbuf, size_t kbuf_len, br_dilithium_private_key *sk);

/**
 * \brief Helper function to load a dilithium public key from an associated buffer
 * 
 * This function will NOT copy any material from the key buffer, as such, 
 * the key buffer MUST remain valid as long as its associated public key structure
 *
 * \param kbuf       Dilithium public key buffer containing the public key material
 * \param kbuf_len   Dilithium public key buffer length
 * \param pk         Dilithium public key structure (destination)
 */
void br_dilithium_keygen_load_public_key(void *kbuf, size_t kbuf_len, br_dilithium_public_key *pk);


#ifdef __cplusplus
}
#endif

#endif
