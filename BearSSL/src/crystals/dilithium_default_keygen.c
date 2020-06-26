#include "inner.h"

/* see bearssl_kyber.h */
br_dilithium_keygen
br_dilithium_keygen_get_default(void)
{
    // TODO Actually implement other versions ?
    return &br_dilithium_third_party_keygen;
}
