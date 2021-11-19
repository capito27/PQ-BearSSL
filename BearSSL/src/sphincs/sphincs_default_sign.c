#include "inner.h"

/* see bearssl_sphincs_p.h */
br_sphincs_p_sign
br_sphincs_p_sign_get_default(void)
{
    return &br_sphincs_p_third_party_sign;
}
