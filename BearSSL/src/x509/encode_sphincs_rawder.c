/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org>
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

// Helper macro to encode into the ASN.1 structure a private or public key field
#define encode_field(dst, src, field) memcpy(dst, src->field, src->field##len); dst += src->field##len;

/* see bearssl_x509.h */
size_t
br_encode_sphincs_p_raw_der(void *dest, const br_sphincs_p_private_key *sk,
	const br_sphincs_p_public_key *pk)
{
		/*
	 * ASN.1 format:
	 *
	 *   SphincsPrivateKey ::= SEQUENCE {
	 *     version        INTEGER { SphincsPrivkeyVer0(0) } (SphincsPrivkeyVer0),
	 *     privateKey     OCTET STRING,
	 *     publicKey      BIT STRING OPTIONAL
	 *   }
	 *
	 * The value of the 'privateKey' field is the raw encoding of 
	 * the private key; Also, leading bytes of value 0x00 
	 * are _not_ removed.
	 *
	 * The 'publicKey' contents are the raw encoded public key.
	 */

	size_t len_version, len_privateKey, len_publicKey;
	size_t len_seq;

	len_version = 3;

	len_privateKey = 1 + len_of_len(BR_SPHINCS_P_SECRET_BUFF_SIZE(sk->mode)+1) + 
						 BR_SPHINCS_P_SECRET_BUFF_SIZE(sk->mode) + 1;
	
	if (pk == NULL) {
		len_publicKey = 0;
	} else {
		len_publicKey =  2 + len_of_len(BR_SPHINCS_P_PUBLIC_BUFF_SIZE(pk->mode)+1) + 
						    BR_SPHINCS_P_PUBLIC_BUFF_SIZE(pk->mode) + 1;
	}
	len_seq = len_version + len_privateKey + len_publicKey;
	if (dest == NULL) {
		return 1 + len_of_len(len_seq) + len_seq;
	} else {
		unsigned char *buf;
		size_t lenlen;

		buf = dest;
		*buf ++ = 0x30;  /* SEQUENCE tag */
		lenlen = br_asn1_encode_length(buf, len_seq);
		buf += lenlen;

		/* version */
		*buf ++ = 0x02; // Integer
		*buf ++ = 0x01; // length
		*buf ++ = 0x00; // 0

		/* privateKey */
		*buf ++ = 0x04; // Octet string
		buf += br_asn1_encode_length(buf, BR_SPHINCS_P_SECRET_BUFF_SIZE(sk->mode) + 1);
		*buf ++ = sk->mode; // Encode the Sphincs mode as the first byte
		encode_field(buf, sk, k);

		/* publicKey */
		if (pk != NULL) {
			*buf ++ = 0x03; // Bit string
			buf += br_asn1_encode_length(buf, BR_SPHINCS_P_PUBLIC_BUFF_SIZE(pk->mode) + 2);
			*buf ++ = 0x00; // Bit offset (there is none)
			*buf ++ = sk->mode; // Encode the Sphincs mode as the first byte
			encode_field(buf, pk, k);
		}

		return 1 + lenlen + len_seq;
	}
}
