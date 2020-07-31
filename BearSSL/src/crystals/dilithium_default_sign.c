#include "inner.h"

/* see bearssl_dilithium.h */
br_dilithium_sign
br_dilithium_sign_get_default(void)
{
    return &br_dilithium_third_party_sign;
}
