CC = /usr/bin/gcc
CFLAGS = -Wall -Wextra -Wpedantic -O3 -ftree-vectorize -mavx512f -mavx512bw -mavx512cd -mavx512vl -ffast-math -march=skylake-avx512 -std=c99 -march=native -fomit-frame-pointer -flto

THASH = simple

SOURCES = 8_times/hash_sha256x8.c 8_times/thash_sha256_$(THASH)x8.c 8_times/sha256x8.c 8_times/sha256avx.c 8_times/utilsx8.c hash_sha256.c 16_times/hash_sha256x16.c thash_sha256_$(THASH).c 16_times/thash_sha256_$(THASH)x16.c sha256.c 16_times/sha256x16.c 16_times/sha256avx512.c address.c randombytes.c merkle.c wots.c utils.c 16_times/utilsx16.c fors.c sign.c
HEADERS = 8_times/hashx8.h 8_times/thashx8.h 8_times/utilsx8.h 8_times/sha256avx.h params.h hash.h 16_times/hashx16.h thash.h 16_times/thashx16.h sha256.h 16_times/sha256x16.h 16_times/sha256avx512.h address.h randombytes.h merkle.h wots.h utils.h 16_times/utilsx16.h fors.h api.h

DET_SOURCES = $(SOURCES:randombytes.%=rng.%)
DET_HEADERS = $(HEADERS:randombytes.%=rng.%)

TESTS = test/fors \
		test/spx \
		test/thashx16 \

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

clean:
	-$(RM) $(TESTS)
	-$(RM) $(BENCHMARK)
	-$(RM) PQCgenKAT_sign
	-$(RM) PQCsignKAT_*.rsp
	-$(RM) PQCsignKAT_*.req
