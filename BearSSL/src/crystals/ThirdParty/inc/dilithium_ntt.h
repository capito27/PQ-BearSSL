#ifndef DILITHIUM_NTT_H
#define DILITHIUM_MTT_H

#include <stdint.h>
#include <stddef.h>

void br_dilithium_third_party_ntt(uint32_t *p, size_t polylen);

void br_dilithium_third_party_invntt_frominvmont(uint32_t *p, size_t polylen);

#endif
