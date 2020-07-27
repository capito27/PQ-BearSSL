#include "inner.h"

/* see bearssl_ssl.h */
void
br_ssl_engine_set_default_kyber(br_ssl_engine_context *cc)
{
    // Only support the third party engine at this point
    br_ssl_engine_set_kyber(cc, br_kyber_decrypt_get_default(), br_kyber_encrypt_get_default(),
                            br_kyber_keygen_get_default(), 2);
}
