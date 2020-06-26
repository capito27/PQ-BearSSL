#include "inner.h"

/* see bearssl_dilithium.h */
br_dilithium_verify
br_dilithium_verify_get_default(void)
{
    // TODO Actually implement other versions ?
    return &br_dilithium_third_party_verify;
}
