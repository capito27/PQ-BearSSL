#include "inner.h"

/* see bearssl_dilithium.h */
br_dilithium_vrfy
br_dilithium_vrfy_get_default(void)
{
    // TODO Actually implement other versions ?
    return &br_dilithium_third_party_vrfy;
}
