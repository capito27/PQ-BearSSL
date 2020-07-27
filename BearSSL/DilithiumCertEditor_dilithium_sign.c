
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>

#include "tools/brssl.h"
#include "bearssl.h"

static int
sign_dilithium(const br_dilithium_private_key *key){
	br_hmac_drbg_context rng;
	br_prng_seeder seeder;

	unsigned char data[100];
	size_t datalen;
	unsigned char sig[BR_DILITHIUM_SIGNATURE_SIZE(BR_DILITHIUM_MAX_SECURITY_MODE)];
	size_t siglen;
	
	// Seed the drbg
	seeder = br_prng_seeder_system(NULL);
	if (seeder == 0) {
		fprintf(stderr, "ERROR: no system source of randomness\n");
		return 1;
	}
	br_hmac_drbg_init(&rng, &br_sha256_vtable, NULL, 0);
	if (!seeder(&rng.vtable)) {
		fprintf(stderr, "ERROR: system source of randomness failed\n");
		return 1;
	}


	// Read the data to sign
	datalen = read(STDIN_FILENO, data, sizeof data);

	siglen = br_dilithium_sign_get_default()(&rng.vtable, key, sig, sizeof sig, data, datalen);

	write(STDOUT_FILENO, sig, siglen);

	return siglen == 0;


}

/* see brssl.h */
int
main(int argc, char *argv[])
{	
	unsigned char buf[100000]; // Should be large enough to hold any sort of relvant key ¯\_(ツ)_/¯
	size_t len;
	br_skey_decoder_context dc;
	int err, ret;

	if (argc < 2){
		return -1;
	}

	len = atoi(argv[1]); // Key length is provided as first argument

	if(!len || len > sizeof buf){ 
		return -1; // Return if invalid or larger than max size
	}

	// Read the raw DER file from STDIN (the first argument is )
	len = read(STDIN_FILENO, buf, len);

	// Initialise the key decoder
	br_skey_decoder_init(&dc);
	br_skey_decoder_push(&dc, buf, len);

	err = br_skey_decoder_last_error(&dc);
	if (err != 0) {
		const char *errname, *errmsg;

		fprintf(stderr, "ERROR (decoding): err=%d\n", err);

		return 1;
	}

	ret = 0;
	switch (br_skey_decoder_key_type(&dc)) {
		const br_dilithium_private_key *dk;

	case BR_KEYTYPE_DLTHM:
		dk = br_skey_decoder_get_dilithium(&dc);
		ret = sign_dilithium(dk);
		break;

	default:
		fprintf(stderr, "Unsupported key type: %d\n",
			br_skey_decoder_key_type(&dc));
		ret = 1;
		break;
	}

	return ret;
	



}
