#include "inner.h"

/* see bearssl_sphincs_p.h */
br_sphincs_p_keygen
br_sphincs_p_keygen_get_default(void)
{
    return &br_sphincs_p_third_party_keygen;
}
