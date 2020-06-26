#include <stdint.h>
#include "fips202.h"
#include "params.h"
#include "sign.h"
#include "randombytes.h"
#include "symmetric.h"
#include "poly.h"
#include "polyvec.h"
#include "packing.h"
#include <stdio.h>

/*************************************************
* Name:        expand_mat
*
* Description: Implementation of ExpandA. Generates matrix A with uniformly
*              random coefficients a_{i,j} by performing rejection
*              sampling on the output stream of SHAKE128(rho|i|j).
*
* Arguments:   - polyvecl mat[K]: output matrix
*              - const unsigned char rho[]: byte array containing seed rho
**************************************************/
void expand_mat(polyvecl mat[K], const unsigned char rho[SEEDBYTES]) {
  unsigned int i, j;

  for(i = 0; i < K; ++i)
    for(j = 0; j < L; ++j)
      poly_uniform(&mat[i].vec[j], rho, (i << 8) + j);
}

/*************************************************
* Name:        challenge
*
* Description: Implementation of H. Samples polynomial with 60 nonzero
*              coefficients in {-1,1} using the output stream of
*              SHAKE256(mu|w1).
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const unsigned char mu[]: byte array containing mu
*              - const polyveck *w1: pointer to vector w1
**************************************************/
void challenge(poly *c,
               const unsigned char mu[CRHBYTES],
               const polyveck *w1)
{
  unsigned int i, b, pos;
  uint64_t signs;
  unsigned char inbuf[CRHBYTES + K*POLW1_SIZE_PACKED];
  unsigned char outbuf[SHAKE256_RATE];
  keccak_state state;

  for(i = 0; i < CRHBYTES; ++i)
    inbuf[i] = mu[i];
  for(i = 0; i < K; ++i)
    polyw1_pack(inbuf + CRHBYTES + i*POLW1_SIZE_PACKED, &w1->vec[i]);

  shake256_absorb(&state, inbuf, sizeof(inbuf));
  shake256_squeezeblocks(outbuf, 1, &state);

  signs = 0;
  for(i = 0; i < 8; ++i)
    signs |= (uint64_t)outbuf[i] << 8*i;

  pos = 8;

  for(i = 0; i < N; ++i)
    c->coeffs[i] = 0;

  for(i = 196; i < 256; ++i) {
    do {
      if(pos >= SHAKE256_RATE) {
        shake256_squeezeblocks(outbuf, 1, &state);
        pos = 0;
      }

      b = outbuf[pos++];
    } while(b > i);

    c->coeffs[i] = c->coeffs[b];
    c->coeffs[b] = 1;
    c->coeffs[b] ^= -(signs & 1) & (1 ^ (Q-1));
    signs >>= 1;
  }
}

/*************************************************
* Name:        crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - unsigned char *pk: pointer to output public key (allocated
*                                   array of CRYPTO_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key (allocated
*                                   array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
  unsigned int i;
  unsigned char seedbuf[3*SEEDBYTES];
  unsigned char tr[CRHBYTES];
  const unsigned char *rho, *rhoprime, *key;
  uint16_t nonce = 0;
  polyvecl mat[K];
  polyvecl s1, s1hat;
  polyveck s2, t, t1, t0;

  /* Expand 32 bytes of randomness into rho, rhoprime and key */
  randombytes(seedbuf, 3*SEEDBYTES);
  rho = seedbuf;
  rhoprime = seedbuf + SEEDBYTES;
  key = seedbuf + 2*SEEDBYTES;
  
#if defined DILITHIUM_TESTING_KEYGEN || defined DILITHIUM_TESTING_SIGN || defined DILITHIUM_TESTING_VERIFY
    // TESTING STUFFS SO THAT I CAN GET PREDICTABLE OUTPUT
  memset(seedbuf, DILITHIUM_RNG_OUTPUT_FORCE, 32 * 3);
#endif

  /* Expand matrix */
  expand_mat(mat, rho);

  /* Sample short vectors s1 and s2 */
  for(i = 0; i < L; ++i)
    poly_uniform_eta(&s1.vec[i], rhoprime, nonce++);

  for(i = 0; i < K; ++i)
    poly_uniform_eta(&s2.vec[i], rhoprime, nonce++);

  /* Matrix-vector multiplication */
  s1hat = s1;
  polyvecl_ntt(&s1hat);
  for(i = 0; i < K; ++i) {
    polyvecl_pointwise_acc_invmontgomery(&t.vec[i], &mat[i], &s1hat);
    poly_reduce(&t.vec[i]);
    poly_invntt_montgomery(&t.vec[i]);
  }

  /* Add error vector s2 */
  polyveck_add(&t, &t, &s2);

  /* Extract t1 and write public key */
  polyveck_freeze(&t);
  polyveck_power2round(&t1, &t0, &t);
  pack_pk(pk, rho, &t1);

  /* Compute CRH(rho, t1) and write secret key */
  crh(tr, pk, CRYPTO_PUBLICKEYBYTES);
  pack_sk(sk, rho, key, tr, &s1, &s2, &t0);
  
#ifdef DILITHIUM_PRINT_KEYGEN
	printf("///////////// KEYGEN /////////////\n");
     // Print the full memory contents of the private and public key
    printf("public key : rho (%ld bytes):\n", SEEDBYTES);
    print_hex_memory(rho, SEEDBYTES);
    printf("public key : t1 (%ld bytes):\n", K*POLT1_SIZE_PACKED);
    print_hex_memory(pk + 32, K*POLT1_SIZE_PACKED);

    printf("private key : rho (%d bytes):\n", SEEDBYTES);
    print_hex_memory(rho, SEEDBYTES);
    printf("private key : key (%d bytes):\n", SEEDBYTES);
    print_hex_memory(key, SEEDBYTES);
    printf("private key : tr (%d bytes):\n", CRHBYTES);
    print_hex_memory(tr, CRHBYTES);
    printf("private key : s1 (%ld bytes):\n", POLETA_SIZE_PACKED*L);
    print_hex_memory(sk + 2*SEEDBYTES + CRHBYTES, POLETA_SIZE_PACKED*L);
    printf("private key : s2 (%ld bytes):\n", POLETA_SIZE_PACKED*K);
    print_hex_memory(sk + 2*SEEDBYTES + CRHBYTES + POLETA_SIZE_PACKED*L, POLETA_SIZE_PACKED*K);
    printf("private key : t0 (%ld bytes):\n", K*POLT0_SIZE_PACKED);
    print_hex_memory(sk + CRYPTO_SECRETKEYBYTES - K*POLT0_SIZE_PACKED, K*POLT0_SIZE_PACKED);
	printf("/////////// KEYGEN END ///////////\n");
#endif

#ifdef DILITHIUM_TESTING_KEYGEN
    exit(-1);
#endif

}



/*************************************************
* Name:        crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - unsigned char *sm: pointer to output signed message (allocated
*                                   array with CRYPTO_BYTES + mlen bytes),
*                                   can be equal to m
*              - unsigned long long *smlen: pointer to output length of signed
*                                           message
*              - const unsigned char *m: pointer to message to be signed
*              - unsigned long long mlen: length of message
*              - const unsigned char *sk: pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign(unsigned char *sm,
                unsigned long long *smlen,
                const unsigned char *m,
                unsigned long long mlen,
                const unsigned char *sk)
{
  unsigned long long i;
  unsigned int n;
  unsigned char seedbuf[2*SEEDBYTES + 3*CRHBYTES];
  unsigned char *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;
  poly c, chat;
  polyvecl mat[K], s1, y, yhat, z;
  polyveck t0, s2, w, w1, w0;
  polyveck h, cs2, ct0;

  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + CRHBYTES;
  mu = key + SEEDBYTES;
  rhoprime = mu + CRHBYTES;
  unpack_sk(rho, key, tr, &s1, &s2, &t0, sk);

  /* Copy tr and message into the sm buffer,
   * backwards since m and sm can be equal in SUPERCOP API */
  for(i = 1; i <= mlen; ++i)
    sm[CRYPTO_BYTES + mlen - i] = m[mlen - i];
  for(i = 0; i < CRHBYTES; ++i)
    sm[CRYPTO_BYTES - CRHBYTES + i] = tr[i];

  /* Compute CRH(tr, msg) */
  crh(mu, sm + CRYPTO_BYTES - CRHBYTES, CRHBYTES + mlen);

#ifdef RANDOMIZED_SIGNING
  randombytes(rhoprime, CRHBYTES);
#else
  crh(rhoprime, key, SEEDBYTES + CRHBYTES);
#endif

  
#if defined DILITHIUM_TESTING_SIGN || defined DILITHIUM_TESTING_VERIFY
    // TESTING STUFFS SO THAT I CAN GET PREDICTABLE OUTPUT
  memset(rhoprime, DILITHIUM_RNG_OUTPUT_FORCE, CRHBYTES);
#endif


  /* Expand matrix and transform vectors */
  expand_mat(mat, rho);
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);

  rej:
  /* Sample intermediate vector y */
  for(i = 0; i < L; ++i)
    poly_uniform_gamma1m1(&y.vec[i], rhoprime, nonce++);

  /* Matrix-vector multiplication */
  yhat = y;
  polyvecl_ntt(&yhat);
  
  for(i = 0; i < K; ++i) {
    polyvecl_pointwise_acc_invmontgomery(&w.vec[i], &mat[i], &yhat);
    poly_reduce(&w.vec[i]);
    poly_invntt_montgomery(&w.vec[i]);
  }

  /* Decompose w and call the random oracle */
  polyveck_csubq(&w);
  
  polyveck_decompose(&w1, &w0, &w);
  challenge(&c, mu, &w1);
  chat = c;
  poly_ntt(&chat);
  
  /* Compute z, reject if it reveals secret */
  for(i = 0; i < L; ++i) {
    poly_pointwise_invmontgomery(&z.vec[i], &chat, &s1.vec[i]);
    poly_invntt_montgomery(&z.vec[i]);
  }
  polyvecl_add(&z, &z, &y);
  polyvecl_freeze(&z);
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    goto rej;

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  for(i = 0; i < K; ++i) {
    poly_pointwise_invmontgomery(&cs2.vec[i], &chat, &s2.vec[i]);
    poly_invntt_montgomery(&cs2.vec[i]);
  }
  polyveck_sub(&w0, &w0, &cs2);
  polyveck_freeze(&w0);

  if(polyveck_chknorm(&w0, GAMMA2 - BETA))
    goto rej;


  /* Compute hints for w1 */
  for(i = 0; i < K; ++i) {
    poly_pointwise_invmontgomery(&ct0.vec[i], &chat, &t0.vec[i]);
    poly_invntt_montgomery(&ct0.vec[i]);
  }

  polyveck_csubq(&ct0);
  if(polyveck_chknorm(&ct0, GAMMA2))
    goto rej;

  polyveck_add(&w0, &w0, &ct0);
  polyveck_csubq(&w0);
  n = polyveck_make_hint(&h, &w0, &w1);
  if(n > OMEGA)
    goto rej;

  /* Write signature */
  pack_sig(sm, &z, &h, &c);

  *smlen = mlen + CRYPTO_BYTES;
  
#ifdef DILITHIUM_PRINT_SIGN
	printf("////////////// SIGN //////////////\n");
    // Print the full memory contents of the signature
    printf("sig : z (%ld bytes):\n", L*POLZ_SIZE_PACKED);
    print_hex_memory(sm, L*POLZ_SIZE_PACKED);
    printf("sig : h (%ld bytes):\n", (OMEGA + K));
    print_hex_memory(sm + L*POLZ_SIZE_PACKED, (OMEGA + K));
    printf("sig : c (%ld bytes):\n", (N/8 + 8));
    print_hex_memory(sm + CRYPTO_BYTES - (N/8 + 8), (N/8 + 8));
	printf("//////////// END SIGN ////////////\n");
#endif

#ifdef DILITHIUM_TESTING_SIGN
    exit(-1);
#endif
  return 0;
  
  
}

/*************************************************
* Name:        crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - unsigned char *m: pointer to output message (allocated
*                                  array with smlen bytes), can be equal to sm
*              - unsigned long long *mlen: pointer to output length of message
*              - const unsigned char *sm: pointer to signed message
*              - unsigned long long smlen: length of signed message
*              - const unsigned char *sk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_open(unsigned char *m,
                     unsigned long long *mlen,
                     const unsigned char *sm,
                     unsigned long long smlen,
                     const unsigned char *pk)
{
  unsigned long long i;
  unsigned char rho[SEEDBYTES];
  unsigned char mu[CRHBYTES];
  poly c, chat, cp;
  polyvecl mat[K], z;
  polyveck t1, w1, h, tmp1, tmp2;

  if(smlen < CRYPTO_BYTES)
    goto badsig;

  *mlen = smlen - CRYPTO_BYTES;

  unpack_pk(rho, &t1, pk);
  if(unpack_sig(&z, &h, &c, sm))
    goto badsig;
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    goto badsig;

  /* Compute CRH(CRH(rho, t1), msg) using m as "playground" buffer */
  if(sm != m)
    for(i = 0; i < *mlen; ++i)
      m[CRYPTO_BYTES + i] = sm[CRYPTO_BYTES + i];

  crh(m + CRYPTO_BYTES - CRHBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  crh(mu, m + CRYPTO_BYTES - CRHBYTES, CRHBYTES + *mlen);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  expand_mat(mat, rho);

  polyvecl_ntt(&z);
  for(i = 0; i < K ; ++i)
    polyvecl_pointwise_acc_invmontgomery(&tmp1.vec[i], &mat[i], &z);

  chat = c;
  poly_ntt(&chat);
  polyveck_shiftl(&t1);
  polyveck_ntt(&t1);
  for(i = 0; i < K; ++i)
    poly_pointwise_invmontgomery(&tmp2.vec[i], &chat, &t1.vec[i]);

  polyveck_sub(&tmp1, &tmp1, &tmp2);
  polyveck_reduce(&tmp1);
  polyveck_invntt_montgomery(&tmp1);

  /* Reconstruct w1 */
  polyveck_csubq(&tmp1);
  polyveck_use_hint(&w1, &tmp1, &h);

  /* Call random oracle and verify challenge */
  challenge(&cp, mu, &w1);
  for(i = 0; i < N; ++i)
    if(c.coeffs[i] != cp.coeffs[i])
      goto badsig;

  /* All good, copy msg, return 0 */
  for(i = 0; i < *mlen; ++i)
    m[i] = sm[CRYPTO_BYTES + i];

#ifdef DILITHIUM_PRINT_VERIFY
	printf("///////////// VERIFY /////////////\n");
    printf("reconstructed challenge polynomial (%ld bytes) : \n", sizeof cp.coeffs);
	print_hex_memory(cp.coeffs, sizeof cp.coeffs);
	printf("/////////// END VERIFY ///////////\n");
#endif

#ifdef DILITHIUM_TESTING_VERIFY
	exit(-1);
#endif

  return 0;

  /* Signature verification failed */
  badsig:
  *mlen = (unsigned long long) -1;
  for(i = 0; i < smlen; ++i)
    m[i] = 0;

  return -1;
}

#if defined DILITHIUM_PRINT_KEYGEN || defined DILITHIUM_PRINT_SIGN || defined DILITHIUM_PRINT_VERIFY
void print_hex_memory(void *mem, size_t length) {
    size_t i;
    unsigned char *p = (unsigned char *) mem;
    for (i = 0; i < length; i++) {
        printf("0x%02x ", p[i]);
        if ((i % 16 == 15) && i < length)
            printf("\n");
    }
    printf("\n");
    return 0;

}
#endif