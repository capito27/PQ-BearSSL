#ifndef BR_BEARSSL_KYBER_H__
#define BR_BEARSSL_KYBER_H__

#include <stddef.h>
#include <stdint.h>

#include "bearssl_hash.h"
#include "bearssl_rand.h"

#ifdef __cplusplus
extern "C" {
#endif

/** \file bearssl_kyber.h
 *
 * # Kyber
 *
 * This file documents the Crystals-Kyber implementation.
 *
 * ## Key Elements
 *
 * Kyber private and public keys consist of a vector of polynomials of degree 255,
 * with the public key containing as well a seed to generate a pseudo-random
 * square polynomial matrix.
 *
 * Additionally, to respect the private key format proposed in the Kyber
 * [white-paper](https://eprint.iacr.org/2017/6341) at page 11, the private key will be
 * stored along with the public key, an intermediary hash (to reduce computation during
 * the decapsulation phase) and a pseudo random value to return in case of decapsulation
 * failure.
 *
 * Such seeds are represented with a 32-byte unsigned char buffer.
 *
 * Such polynomials are represented with a buffer of 256 N-bit integers.
 * 11-bit integers for the public key, and 13-bit integers for the private key.
 *
 * This implementation has been tested to support buffers of 2, 3 or 4 polynomials
 * (AKA, Kyber-512, Kyber-768 and Kyber-1024).
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
 * a length (`size_t`) which is the number of relevant bytes,
 * a pointer to a public key structure, a pointer to the the intermediary
 * hash (`unsigned char *`) as well as a pointer to the pseudo-random failure value.
 */

/**
 * \brief Kyber public key.
 *
 * The structure references the polynomial vector and the seed.
 * The polynomial vector uses two's complement big-endian representation;
 * extra leading bytes of value 0 are NOT allowed.
 * The seed uses unsigned big-endian representation
 */
typedef struct {
    /** \brief compressed polynomial vector. */
    unsigned char *polyvec;
    /** \brief polynomial vector length (in bytes). */
    size_t polyveclen;
    /** \brief Public seed. */
    unsigned char *seed;
    /** \brief polynomial vector length (in bytes). */
    size_t seedlen;
} br_kyber_public_key;

/**
 * \brief Kyber private key.
 *
 * The structure references the polynomial vector, the public key structure,
 * the intermediate hash value and the decapsulation failure pseudo-random value .
 * The polynomial vector, uses two's complement big-endian representation;
 * extra leading bytes of value 0 are NOT allowed.
 */
typedef struct {
    /** \brief compressed polynomial vector. */
    unsigned char *polyvec;
    /** \brief polynomial vector length (in bytes). */
    size_t polyveclen;
    /** \brief public key structure. */
    br_kyber_public_key *polyvec;
    /** \brief intermediary hash */
    unsigned char *hpk
    /** \brief intermediary hash length (in bytes). */
    size_t hpklen;
    /** \brief decapsulation fail seed */
    unsigned char *z
    /** \brief decapsulation fail seed length (in bytes). */
    size_t zlen;
} br_kyber_private_key;

/**
 * \brief Type for a Kyber encapsulation engine.
 *
 * Parameters are:
 *
 *   - A source of random bytes. The source must be already initialized.
 *
 *   - The public key.
 *
 *   - The ciphertext buffer. Its maximum length (in bytes) is provided;
 *     if that length is lower than minimal ciphertext size
 *     expected by the public key length, then an error is reported.
 *
 *   - The shared secret buffer. Its maximum length (in bytes) is provided;
 *     if that length is lower than 32 bytes, then an error is reported.
 *
 * The ciphertext buffer (`ct`, length `ct_max_len`) may NOT overlap with the
 * shared secret buffer (`ss`, length `ss_max_len`).
 *
 * This function returns the actual ciphertext length, in bytes;
 * on error, zero is returned. An error is reported if the output buffer
 * is not large enough, or the shared secret buffer is not large enough,
 * or the public key is invalid.
 *
 * \param rnd          source of random bytes.
 * \param pk           Kyber public key.
 * \param ct           destination buffer.
 * \param ct_max_len   destination buffer length (maximum encrypted data size).
 * \param ss           message to encrypt.
 * \param ss_len       source message length (in bytes).
 * \return  encrypted message length (in bytes), or 0 on error.
 */
typedef size_t (*br_kyber_encrypt)(
        const br_prng_class **rnd,
        const br_kyber_public_key *pk,
        void *ct, size_t ct_max_len,
        void *ss, size_t ss_len);


/**
 * \brief Type for a Kyber decapsulation engine.
 *
 * Parameters are:
 *
 *   - The private key.
 *
 *   - The ciphertext buffer. Its maximum length (in bytes) is provided;
 *     if that length is lower than minimal ciphertext size
 *     expected by the public key length, then an error is reported.
 *
 *   - The shared secret buffer. Its maximum length (in bytes) is provided;
 *     if that length is lower than 32 bytes, then an error is reported.
 *
 * The ciphertext buffer (`ct`, length `ct_len`) may NOT overlap with the
 * shared secret buffer (`ss`, length `ss_max_len`).
 *
 * on error, zero is returned. An error is reported if the ciphertext buffer
 * is not large enough, or the shared secret buffer is not large enough,
 * or decapsulation failed.
 *
 * on error, ss will be undetermined
 *
 * \param sk       Kyber private key.
 * \param ss       shared secret buffer
 * \param ss_len   shared secret buffer (in bytes).
 * \param ct       cipher text buffer buffer.
 * \param ct_len   cipher text length (in bytes).
 * \return  1 on success, 0 on error.
 */
typedef size_t (*br_kyber_decrypt)(
        const br_kyber_private_key *sk,
        void *ss, size_t ss_max_len,
        const void *ct, size_t ct_max_len);

/**
 * \brief kyber encapsulation with the "third party" engine.
 *
 * \see br_kyber_encrypt
 *
 * \param rng_ctx      source of random bytes.
 * \param pk           Kyber public key.
 * \param ct           destination buffer.
 * \param ct_max_len   destination buffer length (maximum encrypted data size).
 * \param ss           message to encrypt.
 * \param ss_len       source message length (in bytes).
 * \return  encrypted message length (in bytes), or 0 on error.
 */
uint32_t br_kyber_third_party_encrypt(
        const br_prng_class **rng_ctx,
        br_kyber_public_key *pk,
        void *ct, size_t ct_max_len,
        void *ss, size_t ss_len);

/**
 * \brief kyber decapsulation with the "third party" engine.
 *
 * \see br_kyber_decrypt
 *
 * \param sk       Kyber private key.
 * \param ss       shared secret buffer
 * \param ss_len   shared secret buffer (in bytes).
 * \param ct       cipher text buffer buffer.
 * \param ct_len   cipher text length (in bytes).
 * \return  1 on success, 0 on error.
 */
uint32_t br_kyber_third_party_decrypt(
        const br_kyber_private_key *sk,
        void *ss, size_t ss_max_len,
        const void *ct, size_t ct_max_len);

/**
 * \brief Get "default" Kyber implementation (encapsultation engine).
 *
 * This returns the preferred implementation of Kyber (encapsultation engine)
 * on the current system.
 *
 * \return  the default implementation.
 */
br_kyber_encrypt br_kyber_encrypt_get_default(void);

/**
 * \brief Get "default" Kyber implementation (decapsultation generation).
 *
 * This returns the preferred implementation of Kyber (decapsulation generation)
 * on the current system.
 *
 * \return  the default implementation.
 */
br_kyber_decrypt br_kyber_decrypt_get_default(void);

/**
 * \brief Get buffer size to hold Kyber public key elements.
 *
 * This macro returns the length (in bytes) of the buffer needed to
 * receive the elements of a Kyber public key, as generated by one of
 * the `br_kyber_*_keygen()` functions. If the provided size is a constant
 * expression, then the whole macro evaluates to a constant expression.
 *
 * \param count   target polynomial count, guaranteed valid from 2 to 4 (included)
 * \return  the length of the public key buffer, in bytes.
 */
#define BR_KYBER_KBUF_PUB_SIZE(count)     ((((256 * 11) / 8) * (count)) + 32)

/**
 * \brief Get buffer size to hold Kyber private key elements.
 *
 * This macro returns the length (in bytes) of the buffer needed to
 * receive the elements of a kyber private key, as generated by one of
 * the `br_kyber_*_keygen()` functions. If the provided size is a constant
 * expression, then the whole macro evaluates to a constant expression.
 *
 * \param count   target polynomial count, guaranteed valid from 2 to 4 (included)
 * \return  the length of the private key buffer, in bytes.
 */
#define BR_KYBER_KBUF_PRIV_SIZE(count)    ((256 * 13 / 8 * (count)) + \
                                        BR_KYBER_KBUF_PUB_SIZE(count) + (2 * 32))


/**
 * \brief Type for Kyber key pair generator implementation.
 *
 * This function generates a new Kyber key pair whose polynomial vector has
 * `count` polynomials. The private key elements are written in the
 * `kbuf_priv` buffer, and pointer values and length fields to these
 * elements are populated in the provided private key structure `sk`.
 * Similarly, the public key elements are written in `kbuf_pub`, with
 * pointers and lengths set in `pk`.
 *
 * If `pk` is `NULL`, then `kbuf_pub` may be `NULL`, and only the
 * private key is set.
 *
 * Only `count` values of 2, 3 and 4 have been tested and validated to work
 *
 * The provided PRNG (`rng_ctx`) must have already been initialized
 * and seeded.
 *
 * Returned value is 1 on success, 0 on error. An error is reported
 * if the requested count is outside of the supported key sizes. Supported
 * range starts at 2 polynomials, and up to an implementation-defined
 * maximum (by default 4 polynomials).
 *
 * \param rng_ctx     source PRNG context (already initialized)
 * \param sk          RSA private key structure (destination)
 * \param kbuf_priv   buffer for private key elements
 * \param pk          RSA public key structure (destination), or `NULL`
 * \param kbuf_pub    buffer for public key elements, or `NULL`
 * \param count       target polynomial vector size (in amount of polynomials)
 * \return  1 on success, 0 on error (invalid parameters)
 */
typedef uint32_t (*br_kyber_keygen)(
        const br_prng_class **rng_ctx,
        br_kyber_private_key *sk, void *kbuf_priv,
        br_kyber_public_key *pk, void *kbuf_pub,
        unsigned size);

/**
 * \brief kyber key pair generation with the "third_party" engine.
 *
 * \see br_kyber_keygen
 *
 * \param rng_ctx     source PRNG context (already initialized)
 * \param sk          RSA private key structure (destination)
 * \param kbuf_priv   buffer for private key elements
 * \param pk          RSA public key structure (destination), or `NULL`
 * \param kbuf_pub    buffer for public key elements, or `NULL`
 * \param size        target RSA modulus size (in bits)
 * \param pubexp      public exponent to use, or zero
 * \return  1 on success, 0 on error (invalid parameters)
 */
uint32_t br_kyber_third_party_keygen(
        const br_prng_class **rng_ctx,
        br_kyber_private_key *sk, void *kbuf_priv,
        br_kyber_public_key *pk, void *kbuf_pub,
        unsigned size);


/**
 * \brief Get "default" RSA implementation (key pair generation).
 *
 * This returns the preferred implementation of RSA (key pair generation)
 * on the current system.
 *
 * \return  the default implementation.
 */
br_kyber_keygen br_kyber_keygen_get_default(void);


#ifdef __cplusplus
}
#endif

#endif
