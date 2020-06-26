#include <stdint.h>
#include "inc/kyber_cbd.h"

/*************************************************
* Name:        load32_littleendian
*
* Description: load bytes into a 32-bit integer
*              in little-endian order
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns 32-bit unsigned integer loaded from x
**************************************************/
static uint32_t br_kyber_third_party_load32_littleendian(const uint8_t x[4]) {
    uint32_t r;
    r = (uint32_t) x[0];
    r |= (uint32_t) x[1] << 8;
    r |= (uint32_t) x[2] << 16;
    r |= (uint32_t) x[3] << 24;
    return r;
}

/*************************************************
* Name:        cbd
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter KYBER_ETA
*
* Arguments:   - poly *r:            pointer to output polynomial
*              - const uint8_t *buf: pointer to input byte array
**************************************************/
void br_kyber_third_party_cbd(br_kyber_third_party_poly *r, const uint8_t *buf) {
        unsigned int i, j;
        uint32_t t, d;
        int16_t a, b;

        for (i = 0; i < sizeof(r->coeffs) / sizeof(r->coeffs[0]) / 8; i++) {
            t = br_kyber_third_party_load32_littleendian(buf + 4 * i);
            d = t & 0x55555555;
            d += (t >> 1) & 0x55555555;

            for (j = 0; j < 8; j++) {
                a = (d >> (4 * j + 0)) & 0x3;
                b = (d >> (4 * j + 2)) & 0x3;
                r->coeffs[8 * i + j] = a - b;
            }
        }

}
