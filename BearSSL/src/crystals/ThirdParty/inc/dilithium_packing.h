#ifndef DILITHIUM_PACKING_H
#define DILITHIUM_PACKING_H

#include <stddef.h>
#include "dilithium_polyvec.h"

void br_dilithium_third_party_pack_pk(br_dilithium_public_key *pk,
                                      const br_dilithium_third_party_polyvec *t1);

void br_dilithium_third_party_pack_sk(br_dilithium_private_key *sk,
                                      const br_dilithium_third_party_polyvec *s1,
                                      const br_dilithium_third_party_polyvec *s2,
                                      const br_dilithium_third_party_polyvec *t0, unsigned mode);

// This function assumes a large enough sig buffer is passed
void br_dilithium_third_party_pack_sig(unsigned char *sig,
                                       const br_dilithium_third_party_polyvec *z,
                                       const br_dilithium_third_party_polyvec *h,
                                       const br_dilithium_third_party_poly *c, unsigned mode);

void br_dilithium_third_party_unpack_pk(br_dilithium_third_party_polyvec *t1,
                                        const br_dilithium_public_key *pk);

void br_dilithium_third_party_unpack_sk(br_dilithium_third_party_polyvec *s1,
                                        br_dilithium_third_party_polyvec *s2,
                                        br_dilithium_third_party_polyvec *t0,
                                        const br_dilithium_private_key *sk);

// This function assumes a large enough sig buffer is passed
int br_dilithium_third_party_unpack_sig(br_dilithium_third_party_polyvec *z,
                                        br_dilithium_third_party_polyvec *h,
                                        br_dilithium_third_party_poly *c,
                                        const unsigned char *sig, unsigned mode);

#endif
