CC = /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -march=native -mtune=native -O3 \
  -fomit-frame-pointer -flto
#CFLAGS += -DUSE_RDPMC
NISTFLAGS = -Wno-unused-result -O3 -march=native -mtune=native
RM = /bin/rm

SOURCES = kem.c indcpa.c polyvec.c poly.c fq.S shuffle.S ntt.S invntt.S \
  basemul.S consts.c rejsample.c cbd.c verify.c
SOURCESKECCAK   = $(SOURCES) fips202.c fips202x4.c symmetric-shake.c \
  keccak4x/KeccakP-1600-times4-SIMD256.o
HEADERS = params.h api.h indcpa.h polyvec.h poly.h reduce.h fq.inc shuffle.inc \
  ntt.h consts.h rejsample.h cbd.h verify.h symmetric.h randombytes.h
HEADERSKECCAK   = $(HEADERS) fips202.h fips202x4.h

.PHONY: all shared clean

all: \
  test_kex512 \
  test_kex768 \
  test_kex1024 \
  PQCgenKAT_kem

shared: \
  pqcrystals_kyber512_avx2.so \
  pqcrystals_kyber768_avx2.so \
  pqcrystals_kyber1024_avx2.so \
  pqcrystals_fips202_ref.so \
  pqcrystals_fips202x4_avx2.so \

keccak4x/KeccakP-1600-times4-SIMD256.o: \
  keccak4x/KeccakP-1600-times4-SIMD256.c \
  keccak4x/KeccakP-1600-times4-SnP.h \
  keccak4x/KeccakP-1600-unrolling.macros \
  keccak4x/SIMD256-config.h \
  keccak4x/align.h \
  keccak4x/brg_endian.h
	$(CC) $(CFLAGS) -c $< -o $@

pqcrystals_fips202_ref.so: fips202.c fips202.h
	$(CC) -shared -fPIC $(CFLAGS) -o $@ $<

pqcrystals_fips202x4_avx2.so: fips202x4.c fips202x4.h \
  keccak4x/KeccakP-1600-times4-SIMD256.o
	$(CC) -shared -fPIC $(CFLAGS) -o $@ $< \
	  keccak4x/KeccakP-1600-times4-SIMD256.o

pqcrystals_aes256ctr_avx2.so: aes256ctr.c aes256ctr.h
	$(CC) -shared -fPIC $(CFLAGS) -o $@ $<

pqcrystals_kyber512_avx2.so: $(SOURCES) $(HEADERS) symmetric-shake.c
	$(CC) -shared -fpic $(CFLAGS) -DKYBER_K=2 $(SOURCES) \
	  symmetric-shake.c -o pqcrystals_kyber512_avx2.so

pqcrystals_kyber768_avx2.so: $(SOURCES) $(HEADERS) symmetric-shake.c
	$(CC) -shared -fpic $(CFLAGS) -DKYBER_K=3 $(SOURCES) \
	  symmetric-shake.c -o pqcrystals_kyber768_avx2.so

pqcrystals_kyber1024_avx2.so: $(SOURCES) $(HEADERS) symmetric-shake.c
	$(CC) -shared -fpic $(CFLAGS) -DKYBER_K=4 $(SOURCES) \
	  symmetric-shake.c -o pqcrystals_kyber1024_avx2.so

test_kex512: $(SOURCESKECCAK) $(HEADERSKECCAK) test_kex.c randombytes.c kex.c kex.h
	$(CC) $(CFLAGS) -DKYBER_K=2 $(SOURCESKECCAK) randombytes.c kex.c test_kex.c -o test_kex512

test_kex768: $(SOURCESKECCAK) $(HEADERSKECCAK) test_kex.c randombytes.c kex.c kex.h
	$(CC) $(CFLAGS) -DKYBER_K=3 $(SOURCESKECCAK) randombytes.c kex.c test_kex.c -o test_kex768

test_kex1024: $(SOURCESKECCAK) $(HEADERSKECCAK) test_kex.c randombytes.c kex.c kex.h
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCESKECCAK) randombytes.c kex.c test_kex.c -o test_kex1024

PQCgenKAT_kem: $(SOURCESKECCAK) $(HEADERSKECCAK) PQCgenKAT_kem.c rng.c rng.h
	$(CC) $(NISTFLAGS) -o $@ $(SOURCESKECCAK) -I. rng.c PQCgenKAT_kem.c -lcrypto

clean:
	-$(RM) -rf *.o *.a *.so
	-$(RM) -rf test_kex512
	-$(RM) -rf test_kex768
	-$(RM) -rf test_kex1024
	-$(RM) -rf PQCgenKAT_kem
	-$(RM) -rf keccak4x/KeccakP-1600-times4-SIMD256.o
