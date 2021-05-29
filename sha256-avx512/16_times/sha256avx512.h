#ifndef SHA256AVX_H
#define SHA256AVX_H
#include "immintrin.h"
#include <stdint.h>

static const unsigned int RC[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define u32 uint32_t
#define u256 __m256i
#define u512 __m512i

#define XOR _mm512_xor_si512
#define OR _mm512_or_si512
#define AND _mm512_and_si512
#define ADD32 _mm512_add_epi32
#define NOT(x) _mm512_xor_si512(x, _mm512_set1_epi32(-1))
#define ANDNOT(a,b) _mm512_andnot_epi32(a,b)

#define LOAD(src) _mm512_loadu_si512((__m512i *)(src))
#define STORE(dest,src) _mm256_storeu_si256((__m256i *)(dest),src)

#define BYTESWAP(x) _mm512_shuffle_epi8(x, _mm512_set_epi32(0xc0d0e0f,0x8090a0b,0x4050607,0x0010203,0xc0d0e0f,0x8090a0b,0x4050607,0x0010203,0xc0d0e0f,0x8090a0b,0x4050607,0x0010203,0xc0d0e0f,0x8090a0b,0x4050607,0x0010203))

#define SHIFTR32(x, y) _mm512_srli_epi32(x, y)
#define SHIFTL32(x, y) _mm512_slli_epi32(x, y)

#define ROTR32(x, y) _mm512_ror_epi32(x,y)
#define ROTL32(x, y) _mm512_rol_epi32(x,y)

#define XOR3(a,b,c) _mm512_ternarylogic_epi32(a,b,c,0x96)

#define ADD3_32(a, b, c) ADD32(ADD32(a, b), c)
#define ADD4_32(a, b, c, d) ADD32(ADD32(ADD32(a, b), c), d)
#define ADD5_32(a, b, c, d, e) ADD32(ADD32(ADD32(ADD32(a, b), c), d), e)

#define MAJ_AVX(a, b, c) _mm512_ternarylogic_epi32(a,b,c,0xE8)
#define CH_AVX(a, b, c) _mm512_ternarylogic_epi32(a,b,c,0xCA)

#define SIGMA1_AVX(x) XOR3(ROTR32(x, 6), ROTR32(x, 11), ROTR32(x, 25))
#define SIGMA0_AVX(x) XOR3(ROTR32(x, 2), ROTR32(x, 13), ROTR32(x, 22))

#define WSIGMA1_AVX(x) XOR3(ROTR32(x, 17), ROTR32(x, 19), SHIFTR32(x, 10))
#define WSIGMA0_AVX(x) XOR3(ROTR32(x, 7), ROTR32(x, 18), SHIFTR32(x, 3))

#define SHA256ROUND_AVX(a, b, c, d, e, f, g, h, rc, w) \
    T0 = ADD5_32(h, SIGMA1_AVX(e), CH_AVX(e, f, g), _mm512_set1_epi32(RC[rc]), w); \
    d = ADD32(d, T0); \
    T1 = ADD32(SIGMA0_AVX(a), MAJ_AVX(a, b, c)); \
    h = ADD32(T0, T1);

typedef struct SHA256state {
    u512 s[8];
    unsigned char msgblocks[16*64];
    int datalen;
    unsigned long long msglen;
} sha256ctx;


void transpose(u512 s[8]);
void sha256_init_frombytes_x16(sha256ctx *ctx, uint8_t *s, unsigned long long msglen);
void sha256_init16x(sha256ctx *ctx);
void sha256_update16x(sha256ctx *ctx, 
                     const unsigned char *d0,
                     const unsigned char *d1,
                     const unsigned char *d2,
                     const unsigned char *d3,
                     const unsigned char *d4,
                     const unsigned char *d5,
                     const unsigned char *d6,
                     const unsigned char *d7,
                     const unsigned char *d8,
                     const unsigned char *d9,
                     const unsigned char *d10,
                     const unsigned char *d11,
                     const unsigned char *d12,
                     const unsigned char *d13,
                     const unsigned char *d14,
                     const unsigned char *d15,
                     unsigned long long len);
void sha256_final16x(sha256ctx *ctx,
                     unsigned char *out0,
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
                     unsigned char *out15);

void sha256_transform16x(sha256ctx *ctx, const unsigned char *data);


#endif
