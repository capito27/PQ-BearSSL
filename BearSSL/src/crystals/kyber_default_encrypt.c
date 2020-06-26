#include "inner.h"

/* see bearssl_kyber.h */
br_kyber_encrypt
br_kyber_encrypt_get_default(void)
{
    // TODO Actually implement other versions ?
    return &br_kyber_third_party_encrypt;
}
