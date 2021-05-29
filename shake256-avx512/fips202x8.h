#ifndef SPX_FIPS202X8_H
#define SPX_FIPS202X8_H

#include <immintrin.h>

void shake128x8(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3,
                unsigned char *out4,
                unsigned char *out5,
                unsigned char *out6,
                unsigned char *out7, unsigned long long outlen,
                unsigned char *in0,
                unsigned char *in1,
                unsigned char *in2,
                unsigned char *in3,
                unsigned char *in4,
                unsigned char *in5,
                unsigned char *in6,
                unsigned char *in7, unsigned long long inlen);

void shake256x8(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3,
                unsigned char *out4,
                unsigned char *out5,
                unsigned char *out6,
                unsigned char *out7, unsigned long long outlen,
                unsigned char *in0,
                unsigned char *in1,
                unsigned char *in2,
                unsigned char *in3,
                unsigned char *in4,
                unsigned char *in5,
                unsigned char *in6,
                unsigned char *in7, unsigned long long inlen);

#endif
