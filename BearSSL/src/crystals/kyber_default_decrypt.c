#include "inner.h"

/* see bearssl_kyber.h */
br_kyber_decrypt
br_kyber_decrypt_get_default(void)
{
    return &br_kyber_third_party_decrypt;
}
