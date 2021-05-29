#ifndef SPX_THASHX16_H
#define SPX_THASHX16_H

#include <stdint.h>

void thashx16(unsigned char *out0,
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
              const unsigned char *in0,
              const unsigned char *in1,
              const unsigned char *in2,
              const unsigned char *in3,
              const unsigned char *in4,
              const unsigned char *in5,
              const unsigned char *in6,
              const unsigned char *in7,
              const unsigned char *in8,
              const unsigned char *in9,
              const unsigned char *in10,
              const unsigned char *in11,
              const unsigned char *in12,
              const unsigned char *in13,
              const unsigned char *in14,
              const unsigned char *in15, unsigned int inblocks,
              const unsigned char *pub_seed, uint32_t addrx16[16*8]);

#endif
