#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "inner.h"
#include "inc/kyber_indcpa.h"
#include "inc/common_poly.h"
#include "inc/common_polyvec.h"
#include "inc/common_ntt.h"



/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   uint8_t *r:          pointer to the output serialized public key
*              polyvec *pk:         pointer to the input public-key polyvec
*              const uint8_t *seed: pointer to the input public seed
**************************************************/
// TODO remove magic numbers, make pk const ?
static void pack_pk(uint8_t *r,
                    size_t rlen,
                    polyvec *pk,
                    const uint8_t *seed,
                    size_t seedlen) {

    if (rlen != pk->veclen * 384 + seedlen || seedlen != 32) {
        // TODO Error handling (status code ?)
        return;
    }

    size_t i;
    polyvec_tobytes(r, rlen, pk);
    // TODO Replace with memcopy ?
    for (i = 0; i < seedlen; i++)
        r[i + 384] = seed[i];
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk:             pointer to output public-key
*                                         polynomial vector
*              - uint8_t *seed:           pointer to output seed to generate
*                                         matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
// TODO remove magic numbers
static void unpack_pk(polyvec *pk,
                      uint8_t *seed,
                      size_t seedlen,
                      const uint8_t *packedpk,
                      size_t packedpklen) {

    if (packedpklen != pk->veclen * 384 + seedlen || seedlen != 32) {
        // TODO Error handling (status code ?)
        return;
    }

    size_t i;
    polyvec_frombytes(pk, packedpk, packedpklen);
    for (i = 0; i < 32; i++)
        seed[i] = packedpk[i + 384];
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - uint8_t *r:  pointer to output serialized secret key
*              - polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
// TODO rlen verification
static void pack_sk(uint8_t *r, size_t rlen, polyvec *sk) {
    polyvec_tobytes(r, rlen, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key;
*              inverse of pack_sk
*
* Arguments:   - polyvec *sk:             pointer to output vector of
*                                         polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
// TODO rlen verification
static void unpack_sk(polyvec *sk, const uint8_t *packedsk, size_t packedsklen) {
    polyvec_frombytes(sk, packedsk, packedsklen);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk:   pointer to the input vector of polynomials b
*              poly *v:    pointer to the input polynomial v
**************************************************/
// TODO rlen verification + remove magic number 320 / 352 / 32
static void pack_ciphertext(uint8_t *r,
                            size_t rlen,
                            polyvec *b,
                            poly *v) {

    if (b->veclen == 2 || b->veclen == 3) {
        polyvec_compress(r, rlen, b);
        // store to r + KYBER_POLYVECCOMPRESSEDBYTES, KYBER_POLYCOMPRESSEDBYTES of data
        poly_compress(r + b->veclen * 320, 32 * (b->veclen + 1), v);
    } else if (b->veclen == 4) {
        polyvec_compress(r, rlen, b);
        poly_compress(r + b->veclen * 352, 32 * (b->veclen + 1), v);
    }
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b:       pointer to the output vector of polynomials b
*              - poly *v:          pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
// TODO clen verification + remove magic number 320 / 352
static void unpack_ciphertext(polyvec *b,
                              poly *v,
                              const uint8_t *c
                              size_t clen) {
    if (b->veclen == 2 || b->veclen == 3) {
        polyvec_decompress(b, c, b->veclen * 320);
        poly_decompress(v, c + b->veclen * 320, 32 * (b->veclen + 1));
    } else if (b->veclen == 4) {
        polyvec_decompress(b, c, b->veclen * 352);
        poly_decompress(v, c + b->veclen * 352, 32 * (b->veclen + 1));
    }
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r:          pointer to output buffer
*              - unsigned int len:    requested number of 16-bit integers
*                                     (uniform mod q)
*              - const uint8_t *buf:  pointer to input buffer
*                                     (assumed to be uniform random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
// TODO remove magic number 3329
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen) {
    unsigned int ctr, pos;
    uint16_t val;

    ctr = pos = 0;
    while (ctr < len && pos + 2 <= buflen) {
        val = buf[pos] | ((uint16_t) buf[pos + 1] << 8);
        pos += 2;

        if (val < 19 * KYBER_Q) {
            val -= (val >> 12) * 3329; // Barrett reduction
            r[ctr++] = (int16_t) val;
        }
    }

    return ctr;
}

#define gen_a(A, B)  gen_matrix(A,B,0)
#define gen_at(A, B) gen_matrix(A,B,1)

/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - polyvec *a:          pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed:      boolean deciding whether A or A^T
*                                     is generated
**************************************************/
// TODO remove define, and use the shake rate provided in the context instead of hardcode

#define GEN_MATRIX_NBLOCKS ((2*256*(1U << 16)/(19*3329) \
                             + 168)/168)

// TODO check polyvec matrix length validity, remove magic numbers,
//  verify that shake output is identical to ref (ref is weird)
void gen_matrix(polyvec *a, size_t alen, const uint8_t *seed, size_t seedlen, int transposed) {
    unsigned int ctr, i, j;
    uint8_t extseed[seedlen + 2];
    uint8_t buf[GEN_MATRIX_NBLOCKS * 168]; // * Shake128 rate
    br_shake_context sc;

    for (i = 0; i < seedlen; i++) {
        extseed[i] = seed[i];
    }

    for (i = 0; i < a->veclen; i++) {
        for (j = 0; j < a->veclen; j++) {
            // Reset the shake state for run
            br_shake_init(&sc, 128);
            if (transposed) {
                extseed[seedlen] = i;
                extseed[seedlen + 1] = j;
            } else {
                extseed[seedlen] = j;
                extseed[seedlen + 1] = i;
            }
            br_shake_inject(&sc, extseed, seedlen + 2);
            br_shake_flip(&sc);
            br_shake_produce(&sc, buf, GEN_MATRIX_NBLOCKS * sc.rate);
            ctr = rej_uniform(a[i].vec[j].coeffs, 256, buf, sizeof(buf));

            while (ctr < 256) {
                br_shake_produce(&sc, buf, sc.rate);
                ctr += rej_uniform(a[i].vec[j].coeffs + ctr, 256 - ctr, buf,
                                   sc.rate);
            }
        }
    }
}

/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
                              (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
**************************************************/

// TODO move this define to somewhere more sensible
#define GET_POLY_VECT_COUNT(pklen) (((pklen) - 32) / 384)

// TODO remove magic numbers

// WIP
void indcpa_keypair(uint8_t *pk, size_t pklen, uint8_t *sk, size_t sklen) {

    unsigned int i;
    uint8_t buf[2 * 32];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + 32;
    uint8_t nonce = 0;

    polyvec a[GET_POLY_VECT_COUNT(pklen)], e, pkpv, skpv;
    for (int j = 0; j < GET_POLY_VECT_COUNT(pklen); ++j) {
    }

//  Generate 32 bytes of random data for the public seed
    randombytes(buf, KYBER_SYMBYTES);

// apply sha3_512 to the random data, to fill the public seed and noiseseed
    hash_g(buf, buf, KYBER_SYMBYTES);


// generate a pseudo-random, uniform looking matrix based on the public seed
    gen_a(a, publicseed);


// Generate noise vector of K 256-term polynomials
// using shake256 with the seed and nonce as input to obtain random bytes
// using those random bytes to generate a polynomial with coefficients close to central binomial distribution
    for (i = 0; i < KYBER_K; i++)
        poly_getnoise(&skpv.vec[i], noiseseed, nonce++);
    for (i = 0; i < KYBER_K; i++)
        poly_getnoise(&e.vec[i], noiseseed, nonce++);

// Apply the negacyclic number-theoretic transform to all polynomials of the vectors
    polyvec_ntt(&skpv);
    polyvec_ntt(&e);

// matrix-vector multiplication
// this will store in the public key polyvec the multiplication of the square matrix a by the secret key polyvec
// and convert the result to montgomery form
    for (i = 0; i < KYBER_K; i++) {
        polyvec_pointwise_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
        poly_tomont(&pkpv.vec[i]);
    }

// Add to the public key polyvec the noise vector e, in such a way as to render the transformation irreversible
    polyvec_add(&pkpv, &pkpv, &e);

// apply barret reduction to return the public key polyvect to a normal form
    polyvec_reduce(&pkpv);

    printf("Buffer content before keygen :n\n");
    for (int i = 0; i < 2 * KYBER_SYMBYTES; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");
// Serialises the secret key polynomial vector into the SK buffer
    pack_sk(sk, &skpv);
// Serialises the public key polynomial vector along with the public seed into the PK buffer
    pack_pk(pk, &pkpv, publicseed);
}

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c:           pointer to output ciphertext
*                                      (of length KYBER_INDCPA_BYTES bytes)
*              - const uint8_t *m:     pointer to input message
*                                      (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk:    pointer to input public key
*                                      (of length KYBER_INDCPA_PUBLICKEYBYTES)
*              - const uint8_t *coins: pointer to input random coins
*                                      used as seed (of length KYBER_SYMBYTES)
*                                      to deterministically generate all
*                                      randomness
**************************************************/

// WIP
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]) {
    unsigned int i;
    uint8_t seed[KYBER_SYMBYTES];
    uint8_t nonce = 0;
    polyvec sp, pkpv, ep, at[KYBER_K], bp;
    poly v, k, epp;

    unpack_pk(&pkpv, seed, pk);
    poly_frommsg(&k, m);
    gen_at(at, seed);

    for (i = 0; i < KYBER_K; i++)
        poly_getnoise(sp.vec + i, coins, nonce++);
    for (i = 0; i < KYBER_K; i++)
        poly_getnoise(ep.vec + i, coins, nonce++);
    poly_getnoise(&epp, coins, nonce++);

    polyvec_ntt(&sp);

    // matrix-vector multiplication
    for (i = 0; i < KYBER_K; i++)
        polyvec_pointwise_acc_montgomery(&bp.vec[i], &at[i], &sp);

    polyvec_pointwise_acc_montgomery(&v, &pkpv, &sp);

    polyvec_invntt_tomont(&bp);
    poly_invntt_tomont(&v);

    polyvec_add(&bp, &bp, &ep);
    poly_add(&v, &v, &epp);
    poly_add(&v, &v, &k);
    polyvec_reduce(&bp);
    poly_reduce(&v);

    pack_ciphertext(c, &bp, &v);
}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m:        pointer to output decrypted message
*                                   (of length KYBER_INDCPA_MSGBYTES)
*              - const uint8_t *c:  pointer to input ciphertext
*                                   (of length KYBER_INDCPA_BYTES)
*              - const uint8_t *sk: pointer to input secret key
*                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/

// WIP
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) {
    polyvec bp, skpv;
    poly v, mp;

    unpack_ciphertext(&bp, &v, c);
    unpack_sk(&skpv, sk);

    polyvec_ntt(&bp);
    polyvec_pointwise_acc_montgomery(&mp, &skpv, &bp);
    poly_invntt_tomont(&mp);

    poly_sub(&mp, &v, &mp);
    poly_reduce(&mp);

    poly_tomsg(m, &mp);
}
