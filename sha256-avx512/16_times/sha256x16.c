#include <string.h>

#include "sha256x16.h"
#include "sha256avx512.h"
#include "../utils.h"

/* This provides a wrapper around the internals of 16x parallel SHA256 */
void sha256x16(unsigned char *out0,
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
               const unsigned char *in15, unsigned long long inlen)
{
    sha256ctx ctx;
    sha256_init16x(&ctx);
    sha256_update16x(&ctx, in0, in1, in2, in3, in4, in5, in6, in7, in8, in9, in10, in11, in12, in13, in14, in15, inlen);
    sha256_final16x(&ctx, out0, out1, out2, out3, out4, out5, out6, out7, out8, out9, out10, out11, out12, out13, out14, out15);
}

/**
 * Note that inlen should be sufficiently small that it still allows for
 * an array to be allocated on the stack. Typically 'in' is merely a seed.
 * Outputs outlen number of bytes
 */
void mgf1x16(unsigned char *outx16, unsigned long outlen,
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
            const unsigned char *in15,
            unsigned long inlen)
{
    unsigned char inbufx16[16*(inlen + 4)];
    unsigned char outbufx16[16*SPX_SHA256_OUTPUT_BYTES];
    unsigned long i;
    unsigned int j;

    memcpy(inbufx16 + 0*(inlen + 4), in0, inlen);
    memcpy(inbufx16 + 1*(inlen + 4), in1, inlen);
    memcpy(inbufx16 + 2*(inlen + 4), in2, inlen);
    memcpy(inbufx16 + 3*(inlen + 4), in3, inlen);
    memcpy(inbufx16 + 4*(inlen + 4), in4, inlen);
    memcpy(inbufx16 + 5*(inlen + 4), in5, inlen);
    memcpy(inbufx16 + 6*(inlen + 4), in6, inlen);
    memcpy(inbufx16 + 7*(inlen + 4), in7, inlen);
    memcpy(inbufx16 + 8*(inlen + 4), in8, inlen);
    memcpy(inbufx16 + 9*(inlen + 4), in9, inlen);
    memcpy(inbufx16 + 10*(inlen + 4), in10, inlen);
    memcpy(inbufx16 + 11*(inlen + 4), in11, inlen);
    memcpy(inbufx16 + 12*(inlen + 4), in12, inlen);
    memcpy(inbufx16 + 13*(inlen + 4), in13, inlen);
    memcpy(inbufx16 + 14*(inlen + 4), in14, inlen);
    memcpy(inbufx16 + 15*(inlen + 4), in15, inlen);

    /* While we can fit in at least another full block of SHA256 output.. */
    for (i = 0; (i+1)*SPX_SHA256_OUTPUT_BYTES <= outlen; i++) {
        for (j = 0; j < 16; j++) {
            u32_to_bytes(inbufx16 + inlen + j*(inlen + 4), i);
        }

        sha256x16(outx16 + 0*outlen,
                  outx16 + 1*outlen,
                  outx16 + 2*outlen,
                  outx16 + 3*outlen,
                  outx16 + 4*outlen,
                  outx16 + 5*outlen,
                  outx16 + 6*outlen,
                  outx16 + 7*outlen,
                  outx16 + 8*outlen,
                  outx16 + 9*outlen,
                  outx16 + 10*outlen,
                  outx16 + 11*outlen,
                  outx16 + 12*outlen,
                  outx16 + 13*outlen,
                  outx16 + 14*outlen,
                  outx16 + 15*outlen,
                  inbufx16 + 0*(inlen + 4),
                  inbufx16 + 1*(inlen + 4),
                  inbufx16 + 2*(inlen + 4),
                  inbufx16 + 3*(inlen + 4),
                  inbufx16 + 4*(inlen + 4),
                  inbufx16 + 5*(inlen + 4),
                  inbufx16 + 6*(inlen + 4),
                  inbufx16 + 7*(inlen + 4),
                  inbufx16 + 8*(inlen + 4),
                  inbufx16 + 9*(inlen + 4),
                  inbufx16 + 10*(inlen + 4),
                  inbufx16 + 11*(inlen + 4),
                  inbufx16 + 12*(inlen + 4),
                  inbufx16 + 13*(inlen + 4),
                  inbufx16 + 14*(inlen + 4),
                  inbufx16 + 15*(inlen + 4), inlen + 4);
         outx16 += SPX_SHA256_OUTPUT_BYTES;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    for (j = 0; j < 16; j++) {
        u32_to_bytes(inbufx16 + inlen + j*(inlen + 4), i);
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
              inbufx16 + 0*(inlen + 4),
              inbufx16 + 1*(inlen + 4),
              inbufx16 + 2*(inlen + 4),
              inbufx16 + 3*(inlen + 4),
              inbufx16 + 4*(inlen + 4),
              inbufx16 + 5*(inlen + 4),
              inbufx16 + 6*(inlen + 4),
              inbufx16 + 7*(inlen + 4),
              inbufx16 + 8*(inlen + 4),
              inbufx16 + 9*(inlen + 4),
              inbufx16 + 10*(inlen + 4),
              inbufx16 + 11*(inlen + 4),
              inbufx16 + 12*(inlen + 4),
              inbufx16 + 13*(inlen + 4),
              inbufx16 + 14*(inlen + 4),
              inbufx16 + 15*(inlen + 4), inlen + 4);
 
    for (j = 0; j < 16; j++) {
        memcpy(outx16 + j*outlen,
               outbufx16 + j*SPX_SHA256_OUTPUT_BYTES,
               outlen - i*SPX_SHA256_OUTPUT_BYTES);
    }
}
