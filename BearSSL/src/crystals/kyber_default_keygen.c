#include "inner.h"

// Macro to easily map contiguous buffer segments to a key section
#define buff_to_key(dst, src, size) dst = (unsigned char *) src; dst##len = size; src += dst##len;

/**
 * \brief Helper function to load a kyber private key from an associated buffer
 * 
 * This function will NOT copy any material from the key buffer, as such, 
 * the key buffer MUST remain valid as long as its associated private key structure
 *
 * \param kbuf       kyber private key buffer containing the private key material
 * \param kbuf_len   Kyber private key buffer length
 * \param sk         Kyber private key structure (destination)
 */
void br_kyber_keygen_load_private_key(void *kbuf, size_t kbuf_len, br_kyber_private_key *sk){
        sk->polynbr = BR_KYBER_PRIVATE_KEY_POLYNOMIAL_COUNT(kbuf_len);
        buff_to_key(sk->privec, kbuf, 384 * sk->polynbr);
        buff_to_key(sk->pubvec, kbuf, 384 * sk->polynbr);
        buff_to_key(sk->seed, kbuf, 32);
        buff_to_key(sk->hpk, kbuf, 32);
        buff_to_key(sk->z, kbuf, 32);
}

/**
 * \brief Helper function to load a kyber public key from an associated buffer
 * 
 * This function will NOT copy any material from the key buffer, as such, 
 * the key buffer MUST remain valid as long as its associated public key structure
 *
 * \param kbuf       kyber public key buffer containing the public key material
 * \param kbuf_len   Kyber public key buffer length
 * \param pk         Kyber public key structure (destination)
 */
void br_kyber_keygen_load_public_key(void *kbuf, size_t kbuf_len, br_kyber_public_key *pk){
        pk->polynbr = BR_KYBER_PUBLIC_KEY_POLYNOMIAL_COUNT(kbuf_len);
        buff_to_key(pk->polyvec, kbuf, 384 * pk->polynbr);
        buff_to_key(pk->seed, kbuf, 32);
}

#undef buff_to_key

/* see bearssl_kyber.h */
br_kyber_keygen
br_kyber_keygen_get_default(void)
{
    // TODO Actually implement other versions ?
    return &br_kyber_third_party_keygen;
}
