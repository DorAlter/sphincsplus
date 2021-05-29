#ifndef SPX_HASHX16_H
#define SPX_HASHX16_H

#include <stdint.h>
#include "../params.h"

void prf_addrx16(unsigned char *out0,
                 unsigned char *out1,
                 unsigned char *out2,
                 unsigned char *out3,
                 unsigned char *out4,
                 unsigned char *out5,
                 unsigned char *out6,
                 unsigned char *out7,
                 unsigned char *out8,
                 unsigned char *out9,
                 unsigned char *out10,
                 unsigned char *out11,
                 unsigned char *out12,
                 unsigned char *out13,
                 unsigned char *out14,
                 unsigned char *out15,
                 const unsigned char *key,
                 const uint32_t addrx8[16*8]);

#endif
