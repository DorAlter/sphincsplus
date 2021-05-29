#include <stdint.h>
#include <string.h>

#include "../address.h"
#include "../utils.h"
#include "../params.h"
#include "thashx16.h"
#include "../sha256.h"
#include "sha256x16.h"
#include "sha256avx512.h"

/**
 * 16-way parallel version of thash; takes 8x as much input and output
 */
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
              const unsigned char *pub_seed, uint32_t addrx16[16*8])
{
    unsigned char bufx16[16*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)];
    unsigned char outbufx16[16*SPX_SHA256_OUTPUT_BYTES];
    unsigned int i;
    sha256ctx ctx;

    (void)pub_seed; /* Suppress an 'unused parameter' warning. */

    sha256_init_frombytes_x16(&ctx, state_seeded, 512);

    for (i = 0; i < 16; i++) {
        memcpy(bufx16 + i*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                         addrx16 + i*8, SPX_SHA256_ADDR_BYTES);
    }

    memcpy(bufx16 + SPX_SHA256_ADDR_BYTES +
        0*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in0, inblocks * SPX_N);
    memcpy(bufx16 + SPX_SHA256_ADDR_BYTES +
        1*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in1, inblocks * SPX_N);
    memcpy(bufx16 + SPX_SHA256_ADDR_BYTES +
        2*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in2, inblocks * SPX_N);
    memcpy(bufx16 + SPX_SHA256_ADDR_BYTES +
        3*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in3, inblocks * SPX_N);
    memcpy(bufx16 + SPX_SHA256_ADDR_BYTES +
        4*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in4, inblocks * SPX_N);
    memcpy(bufx16 + SPX_SHA256_ADDR_BYTES +
        5*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in5, inblocks * SPX_N);
    memcpy(bufx16 + SPX_SHA256_ADDR_BYTES +
        6*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in6, inblocks * SPX_N);
    memcpy(bufx16 + SPX_SHA256_ADDR_BYTES +
        7*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in7, inblocks * SPX_N);
    memcpy(bufx16 + SPX_SHA256_ADDR_BYTES +
        8*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in8, inblocks * SPX_N);
    memcpy(bufx16 + SPX_SHA256_ADDR_BYTES +
        9*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in9, inblocks * SPX_N);
    memcpy(bufx16 + SPX_SHA256_ADDR_BYTES +
        10*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in10, inblocks * SPX_N);
    memcpy(bufx16 + SPX_SHA256_ADDR_BYTES +
        11*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in11, inblocks * SPX_N);
    memcpy(bufx16 + SPX_SHA256_ADDR_BYTES +
        12*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in12, inblocks * SPX_N);
    memcpy(bufx16 + SPX_SHA256_ADDR_BYTES +
        13*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in13, inblocks * SPX_N);
    memcpy(bufx16 + SPX_SHA256_ADDR_BYTES +
        14*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in14, inblocks * SPX_N);
    memcpy(bufx16 + SPX_SHA256_ADDR_BYTES +
        15*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N), in15, inblocks * SPX_N);
    

    sha256_update16x(&ctx,
                     bufx16 + 0*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                     bufx16 + 1*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                     bufx16 + 2*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                     bufx16 + 3*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                     bufx16 + 4*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                     bufx16 + 5*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                     bufx16 + 6*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                     bufx16 + 7*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                     bufx16 + 8*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                     bufx16 + 9*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                     bufx16 + 10*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                     bufx16 + 11*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                     bufx16 + 12*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                     bufx16 + 13*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                     bufx16 + 14*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                     bufx16 + 15*(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                     SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);

    sha256_final16x(&ctx,
                    outbufx16 + 0*SPX_SHA256_OUTPUT_BYTES,
                    outbufx16 + 1*SPX_SHA256_OUTPUT_BYTES,
                    outbufx16 + 2*SPX_SHA256_OUTPUT_BYTES,
                    outbufx16 + 3*SPX_SHA256_OUTPUT_BYTES,
                    outbufx16 + 4*SPX_SHA256_OUTPUT_BYTES,
                    outbufx16 + 5*SPX_SHA256_OUTPUT_BYTES,
                    outbufx16 + 6*SPX_SHA256_OUTPUT_BYTES,
                    outbufx16 + 7*SPX_SHA256_OUTPUT_BYTES,
                    outbufx16 + 8*SPX_SHA256_OUTPUT_BYTES,
                    outbufx16 + 9*SPX_SHA256_OUTPUT_BYTES,
                    outbufx16 + 10*SPX_SHA256_OUTPUT_BYTES,
                    outbufx16 + 11*SPX_SHA256_OUTPUT_BYTES,
                    outbufx16 + 12*SPX_SHA256_OUTPUT_BYTES,
                    outbufx16 + 13*SPX_SHA256_OUTPUT_BYTES,
                    outbufx16 + 14*SPX_SHA256_OUTPUT_BYTES,
                    outbufx16 + 15*SPX_SHA256_OUTPUT_BYTES);

    memcpy(out0, outbufx16 + 0*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out1, outbufx16 + 1*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out2, outbufx16 + 2*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out3, outbufx16 + 3*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out4, outbufx16 + 4*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out5, outbufx16 + 5*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out6, outbufx16 + 6*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out7, outbufx16 + 7*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out8, outbufx16 + 8*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out9, outbufx16 + 9*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out10, outbufx16 + 10*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out11, outbufx16 + 11*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out12, outbufx16 + 12*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out13, outbufx16 + 13*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out14, outbufx16 + 14*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out15, outbufx16 + 15*SPX_SHA256_OUTPUT_BYTES, SPX_N);
}
