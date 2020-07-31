#ifndef PARAMS_H
#define PARAMS_H

///////////// TESTING ///////////////

// This define can be used to force a security level
#define KYBER_K 4

// These define will stop the program after their specific function as well as force the RNG output to the define below
//#define KYBER_TESTING_KEYGEN
//#define KYBER_TESTING_ENC
#define KYBER_TESTING_DEC

// This define sets the RNG to always simulate the return of the following byte
#define KYBER_RNG_OUTPUT_FORCE 0x66

// These define will print the contents of the relevant data
#define KYBER_PRINT_KEYGEN
#define KYBER_PRINT_ENC
#define KYBER_PRINT_DEC

///////////// TESTING ///////////////


#ifndef KYBER_K
#define KYBER_K 2	/* Change this for different security strengths */
#endif

//#define KYBER_90S	/* Uncomment this if you want the 90S variant */

/* Don't change parameters below this line */
#if   (KYBER_K == 2)
#ifdef KYBER_90S
#define KYBER_NAMESPACE(s) pqcrystals_kyber512_90s_ref_##s
#else
#define KYBER_NAMESPACE(s) pqcrystals_kyber512_ref_##s
#endif
#elif (KYBER_K == 3)
#ifdef KYBER_90S
#define KYBER_NAMESPACE(s) pqcrystals_kyber768_90s_ref_##s
#else
#define KYBER_NAMESPACE(s) pqcrystals_kyber768_ref_##s
#endif
#elif (KYBER_K == 4)
#ifdef KYBER_90S
#define KYBER_NAMESPACE(s) pqcrystals_kyber1024_90s_ref_##s
#else
#define KYBER_NAMESPACE(s) pqcrystals_kyber1024_ref_##s
#endif
#else
#error "KYBER_K must be in {2,3,4}"
#endif

#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_ETA 2

#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */

#define KYBER_POLYBYTES		384
#define KYBER_POLYVECBYTES	(KYBER_K * KYBER_POLYBYTES)

#if KYBER_K == 2
#define KYBER_POLYCOMPRESSEDBYTES    96
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 3
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 4
#define KYBER_POLYCOMPRESSEDBYTES    160
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)
#endif

#define KYBER_INDCPA_MSGBYTES       KYBER_SYMBYTES
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES \
                                     + KYBER_POLYCOMPRESSEDBYTES)

#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
/* 32 bytes of additional space to save H(pk) */
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES \
                               + KYBER_INDCPA_PUBLICKEYBYTES \
                               + 2*KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES  KYBER_INDCPA_BYTES

#endif
