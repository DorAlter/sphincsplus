#include <stdint.h>
#include <string.h>

#include "thashx8.h"
#include "address.h"
#include "params.h"

#include "fips202x8.h"

extern void KeccakP1600times8_PermuteAll_24rounds(__m512i *s);

/**
 * 8-way parallel version of thash; takes 8x as much input and output
 */
void thashx8(unsigned char *out0,
             unsigned char *out1,
             unsigned char *out2,
             unsigned char *out3,
             unsigned char *out4,
             unsigned char *out5,
             unsigned char *out6,
             unsigned char *out7, 
             const unsigned char *in0,
             const unsigned char *in1,
             const unsigned char *in2,
             const unsigned char *in3,
             const unsigned char *in4,
             const unsigned char *in5,
             const unsigned char *in6,
             const unsigned char *in7, unsigned int inblocks,
             const unsigned char *pub_seed, uint32_t addrx8[8*8])
{
    if (SPX_N <= 32 && (inblocks == 1 || inblocks == 2)) {
        /* As we write and read only a few quadwords, it is more efficient to
         * build and extract from the fourway SHAKE256 state by hand. */
        __m512i state[25];
        for (int i = 0; i < SPX_N/8; i++) {
            state[i] = _mm512_set1_epi64(((int64_t*)pub_seed)[i]);
        }
        for (int i = 0; i < 4; i++) {
            state[SPX_N/8+i] = _mm512_set_epi32(
            addrx8[7*8+1+2*i],
            addrx8[7*8+2*i],
            addrx8[6*8+1+2*i],
            addrx8[6*8+2*i],
            addrx8[5*8+1+2*i],
            addrx8[5*8+2*i],
            addrx8[4*8+1+2*i],
            addrx8[4*8+2*i],
            addrx8[3*8+1+2*i],
            addrx8[3*8+2*i],
            addrx8[2*8+1+2*i],
            addrx8[2*8+2*i],
            addrx8[8+1+2*i],
            addrx8[8+2*i],
            addrx8[1+2*i],
            addrx8[2*i]
            );
        }

        for (unsigned int i = 0; i < (SPX_N/8) * inblocks; i++) {
            state[SPX_N/8+4+i] = _mm512_set_epi64(
                        ((int64_t*)in7)[i], 
                        ((int64_t*)in6)[i], 
                        ((int64_t*)in5)[i], 
                        ((int64_t*)in4)[i], 
                        ((int64_t*)in3)[i],
                        ((int64_t*)in2)[i],
                        ((int64_t*)in1)[i],
                        ((int64_t*)in0)[i]
                    );
        }

        /* SHAKE domain separator and padding. */
        for (int i = (SPX_N/8)*(1+inblocks)+4; i < 16; i++) {
            state[i] = _mm512_set1_epi64(0);
        }
        state[16] = _mm512_set1_epi64(0x80ll << 56);
        state[(SPX_N/8)*(1+inblocks)+4] = _mm512_xor_si512(
            state[(SPX_N/8)*(1+inblocks)+4],
            _mm512_set1_epi64(0x1f)
        );
        for (int i = 17; i < 25; i++) {
            state[i] = _mm512_set1_epi64(0);
        }

        KeccakP1600times8_PermuteAll_24rounds(&state[0]);
        __m256i_u take1, take2;
            for (int i = 0; i < SPX_N/8; i++) {
                
                (take1) = _mm512_extracti64x4_epi64(state[i],0);
                (take2) = _mm512_extracti64x4_epi64(state[i],1);

                ((int64_t*)out0)[i] = _mm256_extract_epi64(take1, 0);
                ((int64_t*)out1)[i] = _mm256_extract_epi64(take1, 1);
                ((int64_t*)out2)[i] = _mm256_extract_epi64(take1, 2);
                ((int64_t*)out3)[i] = _mm256_extract_epi64(take1, 3);
                ((int64_t*)out4)[i] = _mm256_extract_epi64(take2, 0);
                ((int64_t*)out5)[i] = _mm256_extract_epi64(take2, 1);
                ((int64_t*)out6)[i] = _mm256_extract_epi64(take2, 2);
                ((int64_t*)out7)[i] = _mm256_extract_epi64(take2, 3);
            }
    } else if (SPX_N == 64 && (inblocks == 1 || inblocks == 2)) {
        /* As we write and read only a few quadwords, it is more efficient to
         * build and extract from the fourway SHAKE256 state by hand. */
        __m512i state[25];
        for (int i = 0; i < 8; i++) {
            state[i] = _mm512_set1_epi64(((int64_t*)pub_seed)[i]);
        }
        for (int i = 0; i < 4; i++) {
            state[8+i] = _mm512_set_epi32(
                addrx8[7*8+1+2*i],
                addrx8[7*8+2*i],
                addrx8[6*8+1+2*i],
                addrx8[6*8+2*i],
                addrx8[5*8+1+2*i],
                addrx8[5*8+2*i],
                addrx8[4*8+1+2*i],
                addrx8[4*8+2*i],
                addrx8[3*8+1+2*i],
                addrx8[3*8+2*i],
                addrx8[2*8+1+2*i],
                addrx8[2*8+2*i],
                addrx8[8+1+2*i],
                addrx8[8+2*i],
                addrx8[1+2*i],
                addrx8[2*i]
            );
        }

        for (int i = 17; i < 25; i++) {
            state[i] = _mm512_set1_epi64(0);
        }

        for (unsigned int i = 0; i < 5; i++) {
            state[8+4+i] = _mm512_set_epi64(
                ((int64_t*)in7)[i], 
                ((int64_t*)in6)[i], 
                ((int64_t*)in5)[i], 
                ((int64_t*)in4)[i], 
                ((int64_t*)in3)[i],
                ((int64_t*)in2)[i],
                ((int64_t*)in1)[i],
                ((int64_t*)in0)[i]
            );
        }

        KeccakP1600times8_PermuteAll_24rounds(&state[0]);

        /* Final input. */
        for (unsigned int i = 0; i < 3+8*(inblocks-1); i++) {
            state[i] = _mm512_xor_si512(
                state[i],
                _mm512_set_epi64(
                    ((int64_t*)in7)[i+5],
                    ((int64_t*)in6)[i+5],
                    ((int64_t*)in5)[i+5],
                    ((int64_t*)in4)[i+5],
                    ((int64_t*)in3)[i+5],
                    ((int64_t*)in2)[i+5],
                    ((int64_t*)in1)[i+5],
                    ((int64_t*)in0)[i+5]
                )
            );
        }

        /* Domain separator and padding. */
        state[3+8*(inblocks-1)] = _mm512_xor_si512(state[3+8*(inblocks-1)],
                _mm512_set1_epi64(0x1f));
        state[16] = _mm512_xor_si512(state[16], _mm512_set1_epi64(0x80ll << 56));

        KeccakP1600times8_PermuteAll_24rounds(&state[0]);

        __m256i_u take1, take2;
        for (int i = 0; i < 8; i++) {
            
            (take1) = _mm512_extracti64x4_epi64(state[i],0);
            (take2) = _mm512_extracti64x4_epi64(state[i],1);

            ((int64_t*)out0)[i] = _mm256_extract_epi64(take1, 0);
            ((int64_t*)out1)[i] = _mm256_extract_epi64(take1, 1);
            ((int64_t*)out2)[i] = _mm256_extract_epi64(take1, 2);
            ((int64_t*)out3)[i] = _mm256_extract_epi64(take1, 3);
            ((int64_t*)out4)[i] = _mm256_extract_epi64(take2, 0);
            ((int64_t*)out5)[i] = _mm256_extract_epi64(take2, 1);
            ((int64_t*)out6)[i] = _mm256_extract_epi64(take2, 2);
            ((int64_t*)out7)[i] = _mm256_extract_epi64(take2, 3);
        }
    } else {
        unsigned char buf0[SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N];
        unsigned char buf1[SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N];
        unsigned char buf2[SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N];
        unsigned char buf3[SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N];
        unsigned char buf4[SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N];
        unsigned char buf5[SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N];
        unsigned char buf6[SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N];
        unsigned char buf7[SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N];

        memcpy(buf0, pub_seed, SPX_N);
        memcpy(buf1, pub_seed, SPX_N);
        memcpy(buf2, pub_seed, SPX_N);
        memcpy(buf3, pub_seed, SPX_N);
        memcpy(buf4, pub_seed, SPX_N);
        memcpy(buf5, pub_seed, SPX_N);
        memcpy(buf6, pub_seed, SPX_N);
        memcpy(buf7, pub_seed, SPX_N);
        memcpy(buf0 + SPX_N, addrx8 + 0*8, SPX_ADDR_BYTES);
        memcpy(buf1 + SPX_N, addrx8 + 1*8, SPX_ADDR_BYTES);
        memcpy(buf2 + SPX_N, addrx8 + 2*8, SPX_ADDR_BYTES);
        memcpy(buf3 + SPX_N, addrx8 + 3*8, SPX_ADDR_BYTES);
        memcpy(buf4 + SPX_N, addrx8 + 4*8, SPX_ADDR_BYTES);
        memcpy(buf5 + SPX_N, addrx8 + 5*8, SPX_ADDR_BYTES);
        memcpy(buf6 + SPX_N, addrx8 + 6*8, SPX_ADDR_BYTES);
        memcpy(buf7 + SPX_N, addrx8 + 7*8, SPX_ADDR_BYTES);
        memcpy(buf0 + SPX_N + SPX_ADDR_BYTES, in0, inblocks * SPX_N);
        memcpy(buf1 + SPX_N + SPX_ADDR_BYTES, in1, inblocks * SPX_N);
        memcpy(buf2 + SPX_N + SPX_ADDR_BYTES, in2, inblocks * SPX_N);
        memcpy(buf3 + SPX_N + SPX_ADDR_BYTES, in3, inblocks * SPX_N);
        memcpy(buf4 + SPX_N + SPX_ADDR_BYTES, in4, inblocks * SPX_N);
        memcpy(buf5 + SPX_N + SPX_ADDR_BYTES, in5, inblocks * SPX_N);
        memcpy(buf6 + SPX_N + SPX_ADDR_BYTES, in6, inblocks * SPX_N);
        memcpy(buf7 + SPX_N + SPX_ADDR_BYTES, in7, inblocks * SPX_N);



        shake256x8(out0, out1, out2, out3,out4, out5, out6, out7, SPX_N,
                   buf0, buf1, buf2, buf3,buf4, buf5, buf6, buf7, SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N);
    }
}
