#include <stdint.h>
#include <string.h>

#include "address.h"
#include "params.h"
#include "fips202x8.h" 
#include "hashx8.h"

extern void KeccakP1600times8_PermuteAll_24rounds(__m512i *s);

/*
 * 8-way parallel version of prf_addr; takes 8x as much input and output
 */
void prf_addrx8(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3,
                unsigned char *out4,
                unsigned char *out5,
                unsigned char *out6,
                unsigned char *out7,
                const unsigned char *key,
                const uint32_t addrx8[8*8]) {
    /* As we write and read only a few quadwords, it is more efficient to
     * build and extract from the fourway SHAKE256 state by hand. */
    __m512i state[25];
    
    for (int i = 0; i < SPX_N/8; i++) {
        state[i] = _mm512_set1_epi64(((int64_t*)key)[i]);
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

    /* SHAKE domain separator and padding. */
    state[SPX_N/8+4] = _mm512_set1_epi64(0x1f);
    for (int i = SPX_N/8+5; i < 16; i++) {
        state[i] = _mm512_set1_epi64(0);
    }
    state[16] = _mm512_set1_epi64(0x80ll << 56); 

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
}

