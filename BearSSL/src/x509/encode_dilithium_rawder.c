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
br_encode_dilithium_raw_der(void *dest, const br_dilithium_private_key *sk,
	const br_dilithium_public_key *pk)
{
		/*
	 * ASN.1 format:
	 *
	 *   DilithiumPrivateKey ::= SEQUENCE {
	 *     version        INTEGER { DilithiumPrivkeyVer0(0) } (DilithiumPrivkeyVer0),
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

	len_privateKey = 1 + len_of_len(BR_DILITHIUM_SECRET_BUFF_SIZE(sk->mode)) + 
						 BR_DILITHIUM_SECRET_BUFF_SIZE(sk->mode);
	
	if (pk == NULL) {
		len_publicKey = 0;
	} else {
		len_publicKey =  2 + len_of_len(BR_DILITHIUM_PUBLIC_BUFF_SIZE(pk->mode)) + 
						    BR_DILITHIUM_PUBLIC_BUFF_SIZE(pk->mode);
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
		buf += br_asn1_encode_length(buf, BR_DILITHIUM_SECRET_BUFF_SIZE(sk->mode));
		encode_field(buf, sk, rho);
		encode_field(buf, sk, key);
		encode_field(buf, sk, tr);
		encode_field(buf, sk, s1);
		encode_field(buf, sk, s2);
		encode_field(buf, sk, t0);

		/* publicKey */
		if (pk != NULL) {
			*buf ++ = 0x03; // Bit string
			buf += br_asn1_encode_length(buf, BR_DILITHIUM_PUBLIC_BUFF_SIZE(pk->mode) + 1);
			*buf ++ = 0x00; // Bit offset (there is none)
			encode_field(buf, pk, rho);
			encode_field(buf, pk, t1);
		}

		return 1 + lenlen + len_seq;
	}
}
