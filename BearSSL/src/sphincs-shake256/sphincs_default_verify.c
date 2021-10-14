#include "inner.h"

/* see bearssl_sphincs_p.h */
br_sphincs_p_vrfy
br_sphincs_p_vrfy_get_default(void)
{
    return &br_sphincs_p_third_party_vrfy;
}
