#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "common_poly.h"

void br_kyber_cbd(poly *r, const uint8_t *buf, size_t buflen);

#endif
