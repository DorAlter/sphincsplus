#include <stdint.h>
#include <string.h>

#include "../address.h"
#include "../utils.h"
#include "../params.h"
#include "hashx16.h"
#include "../sha256.h"
#include "sha256x16.h"
#include "sha256avx512.h"

/*
 * 16-way parallel version of prf_addr; takes 16x as much input and output
 */
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
                 const uint32_t addrx16[16*8])
{
    unsigned char bufx16[16 * (SPX_N + SPX_SHA256_ADDR_BYTES)];
    unsigned char outbufx16[16 * SPX_SHA256_OUTPUT_BYTES];
    unsigned int j;

    for (j = 0; j < 16; j++) {
        memcpy(bufx16 + j*(SPX_N + SPX_SHA256_ADDR_BYTES), key, SPX_N);
        memcpy(bufx16 + SPX_N + j*(SPX_N + SPX_SHA256_ADDR_BYTES),
                         addrx16 + j*8, SPX_SHA256_ADDR_BYTES);
    }

    sha256x16(outbufx16 + 0*SPX_SHA256_OUTPUT_BYTES,
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
              outbufx16 + 15*SPX_SHA256_OUTPUT_BYTES,
              bufx16 + 0*(SPX_N + SPX_SHA256_ADDR_BYTES),
              bufx16 + 1*(SPX_N + SPX_SHA256_ADDR_BYTES),
              bufx16 + 2*(SPX_N + SPX_SHA256_ADDR_BYTES),
              bufx16 + 3*(SPX_N + SPX_SHA256_ADDR_BYTES),
              bufx16 + 4*(SPX_N + SPX_SHA256_ADDR_BYTES),
              bufx16 + 5*(SPX_N + SPX_SHA256_ADDR_BYTES),
              bufx16 + 6*(SPX_N + SPX_SHA256_ADDR_BYTES),
              bufx16 + 7*(SPX_N + SPX_SHA256_ADDR_BYTES),
              bufx16 + 8*(SPX_N + SPX_SHA256_ADDR_BYTES),
              bufx16 + 9*(SPX_N + SPX_SHA256_ADDR_BYTES),
              bufx16 + 10*(SPX_N + SPX_SHA256_ADDR_BYTES),
              bufx16 + 11*(SPX_N + SPX_SHA256_ADDR_BYTES),
              bufx16 + 12*(SPX_N + SPX_SHA256_ADDR_BYTES),
              bufx16 + 13*(SPX_N + SPX_SHA256_ADDR_BYTES),
              bufx16 + 14*(SPX_N + SPX_SHA256_ADDR_BYTES),
              bufx16 + 15*(SPX_N + SPX_SHA256_ADDR_BYTES),
              SPX_N + SPX_SHA256_ADDR_BYTES);

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
