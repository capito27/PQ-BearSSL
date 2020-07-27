/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "inner.h"
#include "assert.h"

static void
cc_none0(const br_ssl_client_certificate_class **pctx)
{
	(void)pctx;
}

static void
cc_none1(const br_ssl_client_certificate_class **pctx, size_t len)
{
	(void)pctx;
	(void)len;
}

static void
cc_none2(const br_ssl_client_certificate_class **pctx,
	const unsigned char *data, size_t len)
{
	(void)pctx;
	(void)data;
	(void)len;
}

static void
cc_choose(const br_ssl_client_certificate_class **pctx,
	const br_ssl_client_context *cc, uint32_t auth_types,
	br_ssl_client_certificate *choices)
{
	br_ssl_client_certificate_dilithium_context *zc;
	int x;

	(void)cc;

	zc = (br_ssl_client_certificate_dilithium_context *)pctx;

	x = br_ssl_choose_hash((unsigned)(auth_types >> 25));
	if (x == 0) {
		memset(choices, 0, sizeof *choices);
		return;
	}
	choices->auth_type = BR_AUTH_DILITHIUM;
	choices->hash_id = x;
	choices->chain = zc->chain;
	choices->chain_len = zc->chain_len;
}

static uint32_t
cc_do_keyx(const br_ssl_client_certificate_class **pctx,
	unsigned char *data, size_t *len)
{
	// Since Dilithium key are not used for key exchanges, only for signatures,
	// We abort
	(void)pctx;
	(void)data;
	(void)len;
	assert(0);
}

static size_t
cc_do_sign(const br_ssl_client_certificate_class **pctx,
	int hash_id, size_t hv_len, unsigned char *data, size_t len)
{
	br_ssl_client_certificate_dilithium_context *zc;
	unsigned char hv[64];
	br_hmac_drbg_context rng;
	br_prng_seeder seeder;
	
	(void)hash_id;

	zc = (br_ssl_client_certificate_dilithium_context *)pctx;
	memcpy(hv, data, hv_len);

	if (len < BR_DILITHIUM_SIGNATURE_SIZE(zc->sk->mode)) {
		return 0;
	}
	// Seed the drbg
	seeder = br_prng_seeder_system(NULL);
	if (seeder == 0) {
		return 0;
	}
	br_hmac_drbg_init(&rng, &br_sha256_vtable, NULL, 0);
	if (!seeder(&rng.vtable)) {
		return 0;
	}
	return zc->idilithium(&rng.vtable, zc->sk, data, len, hv, hv_len);
}

static const br_ssl_client_certificate_class ccert_vtable = {
	sizeof(br_ssl_client_certificate_dilithium_context),
	cc_none0, /* start_name_list */
	cc_none1, /* start_name */
	cc_none2, /* append_name */
	cc_none0, /* end_name */
	cc_none0, /* end_name_list */
	cc_choose,
	cc_do_keyx,
	cc_do_sign
};

/* see bearssl_ssl.h */
void
br_ssl_client_set_single_dilithium(br_ssl_client_context *cc,
	const br_x509_certificate *chain, size_t chain_len,
	const br_dilithium_private_key *sk,
	unsigned cert_issuer_key_type, br_dilithium_sign idilithium)
{
	cc->client_auth.single_dilithium.vtable = &ccert_vtable;
	cc->client_auth.single_dilithium.chain = chain;
	cc->client_auth.single_dilithium.chain_len = chain_len;
	cc->client_auth.single_dilithium.sk = sk;
	cc->client_auth.single_dilithium.issuer_key_type = cert_issuer_key_type;
	cc->client_auth.single_dilithium.mhash = &cc->eng.mhash;
	cc->client_auth.single_dilithium.idilithium = idilithium;
	cc->client_auth_vtable = &cc->client_auth.single_dilithium.vtable;
}
