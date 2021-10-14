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
	br_ssl_client_certificate_sphincs_p_context *zc;
	int x;

	(void)cc;

	zc = (br_ssl_client_certificate_sphincs_p_context *)pctx;

	x = br_ssl_choose_hash((unsigned)(auth_types >> 25));
	if (x == 0) {
		memset(choices, 0, sizeof *choices);
		return;
	}
	choices->auth_type = BR_AUTH_SPHINCS;
	choices->hash_id = x;
	choices->chain = zc->chain;
	choices->chain_len = zc->chain_len;
}

static uint32_t
cc_do_keyx(const br_ssl_client_certificate_class **pctx,
	unsigned char *data, size_t *len)
{
	// Since Sphincs key are not used for key exchanges, only for signatures,
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
	br_ssl_client_certificate_sphincs_p_context *zc;
	unsigned char hv[64];
	
	(void)hash_id;

	zc = (br_ssl_client_certificate_sphincs_p_context *)pctx;
	memcpy(hv, data, hv_len);

	if (len < BR_SPHINCS_P_SIGNATURE_SIZE(zc->sk->mode)) {
		return 0;
	}
	return zc->isphincs_p(zc->sk, data, len, hv, hv_len);
}

static const br_ssl_client_certificate_class ccert_vtable = {
	sizeof(br_ssl_client_certificate_sphincs_p_context),
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
br_ssl_client_set_single_sphincs_p(br_ssl_client_context *cc,
	const br_x509_certificate *chain, size_t chain_len,
	const br_sphincs_p_private_key *sk,
	unsigned cert_issuer_key_type, br_sphincs_p_sign isphincs_p)
{
	cc->client_auth.single_sphincs_p.vtable = &ccert_vtable;
	cc->client_auth.single_sphincs_p.chain = chain;
	cc->client_auth.single_sphincs_p.chain_len = chain_len;
	cc->client_auth.single_sphincs_p.sk = sk;
	cc->client_auth.single_sphincs_p.issuer_key_type = cert_issuer_key_type;
	cc->client_auth.single_sphincs_p.mhash = &cc->eng.mhash;
	cc->client_auth.single_sphincs_p.isphincs_p = isphincs_p;
	cc->client_auth_vtable = &cc->client_auth.single_sphincs_p.vtable;
}
