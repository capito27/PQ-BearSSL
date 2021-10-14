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

static int
se_choose(const br_ssl_server_policy_class **pctx,
	const br_ssl_server_context *cc,
	br_ssl_server_choices *choices)
{
	br_ssl_server_policy_sphincs_p_context *pc;
	const br_suite_translated *st;
	size_t u, st_num;
	unsigned hash_id;

	pc = (br_ssl_server_policy_sphincs_p_context *)pctx;
	st = br_ssl_server_get_client_suites(cc, &st_num);
	hash_id = br_ssl_choose_hash(br_ssl_server_get_client_hashes(cc) >> 8);
	if (cc->eng.session.version < BR_TLS12) {
		hash_id = br_sha1_ID;
	}
	choices->chain = pc->chain;
	choices->chain_len = pc->chain_len;
	for (u = 0; u < st_num; u ++) {
		unsigned tt;

		tt = st[u][1];
		switch (tt >> 12) {
		case BR_SSLKEYX_KYBR_SPHINCS:
			if (hash_id != 0)
			{
				choices->cipher_suite = st[u][0];
				choices->algo_id = hash_id + 0xFF00;
				return 1;
			}
			break;
		}
	}
	return 0;
}

static uint32_t
se_do_keyx(const br_ssl_server_policy_class **pctx,
	unsigned char *data, size_t *len)
{
	(void)pctx;
	(void)data;
	(void)len;
	// Unimplemented for sphincs certificates
	assert(0);
	return 0;
}

static size_t
se_do_sign(const br_ssl_server_policy_class **pctx,
	unsigned algo_id, unsigned char *data, size_t hv_len, size_t len)
{
	br_ssl_server_policy_sphincs_p_context *pc;
	unsigned char hv[64];

	algo_id &= 0xFF;
	pc = (br_ssl_server_policy_sphincs_p_context *)pctx;
	memcpy(hv, data, hv_len);
	if (len < BR_SPHINCS_P_SIGNATURE_SIZE(pc->sk->mode)) {
		return 0;
	}
	return pc->isphincs_p(pc->sk, data, len, hv, hv_len);
}

static const br_ssl_server_policy_class se_policy_vtable = {
	sizeof(br_ssl_server_policy_sphincs_p_context),
	se_choose,
	se_do_keyx,
	se_do_sign
};

/* see bearssl_ssl.h */
void
br_ssl_server_set_single_sphincs_p(br_ssl_server_context *cc,
	const br_x509_certificate *chain, size_t chain_len,
	const br_sphincs_p_private_key *sk, br_sphincs_p_sign isphincs_p)
{
	cc->chain_handler.single_sphincs_p.vtable = &se_policy_vtable;
	cc->chain_handler.single_sphincs_p.chain = chain;
	cc->chain_handler.single_sphincs_p.chain_len = chain_len;
	cc->chain_handler.single_sphincs_p.sk = sk;
	cc->chain_handler.single_sphincs_p.mhash = &cc->eng.mhash;
	cc->chain_handler.single_sphincs_p.isphincs_p = isphincs_p;
	cc->policy_vtable = &cc->chain_handler.single_sphincs_p.vtable;
}
