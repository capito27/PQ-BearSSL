#include "inner.h"


/* see bearssl_kyber.h */
br_dilithium_public_key_derivate
br_dilithium_public_key_derivate_get_default(void)
{
    return &br_dilithium_third_party_public_key_derivate;
}
