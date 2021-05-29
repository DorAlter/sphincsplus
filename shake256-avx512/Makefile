CC = /usr/bin/gcc
CFLAGS = -Wall -Wextra -Wpedantic -O3 -mavx512f -mavx512bw -mavx512cd -ffast-math -std=c99 -march=native -fomit-frame-pointer -flto

THASH = simple

SOURCES =          hash_shake256.c hash_shake256x8.c thash_shake256_$(THASH).c thash_shake256_$(THASH)x8.c address.c randombytes.c merkle.c wots.c utils.c utilsx8.c fors.c sign.c fips202.c fips202x8.c keccak8x/KeccakP-1600-times8-SIMD512.o
HEADERS = params.h hash.h          hashx8.h          thash.h                 thashx8.h                 address.h randombytes.h merkle.h wots.h utils.h utilsx8.h fors.h api.h fips202.h fips202x8.h

DET_SOURCES = $(SOURCES:randombytes.%=rng.%)
DET_HEADERS = $(HEADERS:randombytes.%=rng.%)

TESTS = test/fors \
		test/spx \
		test/thashx8 \

BENCHMARK = test/benchmark

.PHONY: clean test benchmark

default: PQCgenKAT_sign

all: PQCgenKAT_sign tests benchmarks

tests: $(TESTS)

test: $(TESTS:=.exec)

benchmarks: $(BENCHMARK)

benchmark: $(BENCHMARK:=.exec)

PQCgenKAT_sign: PQCgenKAT_sign.c $(DET_SOURCES) $(DET_HEADERS)
	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto

test/%: test/%.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/%.exec: test/%
	@$<

keccak8x/KeccakP-1600-times8-SIMD512.o: keccak8x/align.h \
										keccak8x/brg_endian.h \
										keccak8x/KeccakP-1600-times8-SIMD512.c \
										keccak8x/KeccakP-1600-times8-SnP.h \
										keccak8x/KeccakP-1600-unrolling.macros \
										keccak8x/SIMD512-config.h
	$(CC) $(CFLAGS) -c keccak8x/KeccakP-1600-times8-SIMD512.c -o $@

clean:
	-$(RM) keccak8x/KeccakP-1600-times8-SIMD512.o
	-$(RM) $(TESTS)
	-$(RM) $(BENCHMARK)
	-$(RM) PQCgenKAT_sign
	-$(RM) PQCsignKAT_*.rsp
	-$(RM) PQCsignKAT_*.req
