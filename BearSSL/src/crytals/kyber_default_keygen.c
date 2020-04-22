#include "inner.h"

/* see bearssl_kyber.h */
br_kyber_keygen
br_kyber_keygen_get_default(void)
{
    // TODO Actually implement other versions ?
    return &br_kyber_third_party_keygen;
}
