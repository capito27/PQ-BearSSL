#include "inner.h"


// Valid computation for security levels 1 through 4
#define polyeta_packed(mode) ((mode) <= 3 ? 128 : 96)

// Macro to easily map contiguous buffer segments to a key section
#define buff_to_key(dst, src, size) dst = (unsigned char *) src; dst##len = size; src = (unsigned char *) src + dst##len;

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
void br_dilithium_keygen_load_private_key(void *kbuf, size_t kbuf_len, br_dilithium_private_key *sk){
    sk->mode = BR_DILITHIUM_SECRET_KEY_MODE(kbuf_len);
    buff_to_key(sk->rho, kbuf, 32);
    buff_to_key(sk->key, kbuf, 32);
    buff_to_key(sk->tr, kbuf, 48);
    buff_to_key(sk->s1, kbuf, (sk->mode + 1) * polyeta_packed(sk->mode));
    buff_to_key(sk->s2, kbuf, (sk->mode + 2) * polyeta_packed(sk->mode));
    buff_to_key(sk->t0, kbuf, (sk->mode + 2) * 448);
}

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
void br_dilithium_keygen_load_public_key(void *kbuf, size_t kbuf_len, br_dilithium_public_key *pk){
    pk->mode = BR_DILITHIUM_PUBLIC_KEY_MODE(kbuf_len);
    buff_to_key(pk->rho, kbuf, 32);
    buff_to_key(pk->t1, kbuf, (pk->mode + 2) * 288);
}

#undef buff_to_key
#undef polyeta_packed

/* see bearssl_kyber.h */
br_dilithium_keygen
br_dilithium_keygen_get_default(void)
{
    // TODO Actually implement other versions ?
    return &br_dilithium_third_party_keygen;
}
