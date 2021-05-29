#include <stdio.h>
#include <string.h>

#include "../16_times/thashx16.h"
#include "../thash.h"
#include "../randombytes.h"
#include "../params.h"
#include "../hash.h"

int main()
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    unsigned char input[16*SPX_N];
    unsigned char seed[SPX_N];
    unsigned char output[16*SPX_N];
    unsigned char out16[16*SPX_N];
    uint32_t addr[16*8] = {0};
    unsigned int j;

    randombytes(seed, SPX_N);
    randombytes(input, 16*SPX_N);
    randombytes((unsigned char *)addr, 16 * 8 * sizeof(uint32_t));

    initialize_hash_function(seed, seed);

    printf("Testing if thash matches thashx16.. ");

    for (j = 0; j < 16; j++) {
        thash(out16 + j * SPX_N, input + j * SPX_N, 1, seed, addr + j*8);
    }

    thashx16(output + 0*SPX_N,
             output + 1*SPX_N,
             output + 2*SPX_N,
             output + 3*SPX_N,
             output + 4*SPX_N,
             output + 5*SPX_N,
             output + 6*SPX_N,
             output + 7*SPX_N,
             output + 8*SPX_N,
             output + 9*SPX_N,
             output + 10*SPX_N,
             output + 11*SPX_N,
             output + 12*SPX_N,
             output + 13*SPX_N,
             output + 14*SPX_N,
             output + 15*SPX_N,
             input + 0*SPX_N,
             input + 1*SPX_N,
             input + 2*SPX_N,
             input + 3*SPX_N,
             input + 4*SPX_N,
             input + 5*SPX_N,
             input + 6*SPX_N,
             input + 7*SPX_N,
             input + 8*SPX_N,
             input + 9*SPX_N,
             input + 10*SPX_N,
             input + 11*SPX_N,
             input + 12*SPX_N,
             input + 13*SPX_N,
             input + 14*SPX_N,
             input + 15*SPX_N,
             1, seed, addr);

    if (memcmp(out16, output, 16 * SPX_N)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");
    return 0;
}
