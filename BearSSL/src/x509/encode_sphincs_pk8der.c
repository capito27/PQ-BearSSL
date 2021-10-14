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

/* see bearssl_x509.h */
size_t
br_encode_sphincs_p_pkcs8_der(void *dest, const br_sphincs_p_private_key *sk,
	const br_sphincs_p_public_key *pk)
{
	/*
	 * ASN.1 format:
	 *
	 *   OneAsymmetricKey ::= SEQUENCE {
	 *     version                   Version,
	 *     privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
	 *     privateKey                PrivateKey,
	 *     attributes            [0] Attributes OPTIONAL,
	 *     ...,
	 *     [[2: publicKey        [1] PublicKey OPTIONAL ]],
	 *     ...
	 *   }
	 *
	 * We don't include attributes or public key (the public key
	 * is included in the private key value instead). The
	 * 'version' field is an INTEGER that we will set to 0
	 * (meaning 'v1', compatible with previous versions of PKCS#8).
	 * The 'privateKeyAlgorithm' structure is an AlgorithmIdentifier
	 * whose OID should be the custom id-sphincsPublicKey.
	 * The 'privateKey' is an OCTET STRING, whose value
	 * is the "raw DER" encoding of the key pair.
	 */

	/*
	 * OID id-sphincsPublicKey (1.2.840.10045.2.2), DER-encoded (with
	 * the tag). 
	 * CUSTOM OID inserted into the 1.2.840.10045.2 OID structure
	 * for ECDSA from ANSI X9.62 standard (1998).
	 */
	static const unsigned char OID_SPHINCSPUBKEY[] = {
		0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x02
	};

	size_t len_version, len_privateKeyAlgorithm, len_privateKeyValue;
	size_t len_privateKey, len_seq;

	len_version = 3;
	len_privateKeyAlgorithm = 2 + sizeof OID_SPHINCSPUBKEY;
	len_privateKeyValue = br_encode_sphincs_p_raw_der(NULL, sk, pk);
	len_privateKey = 1 + len_of_len(len_privateKeyValue)
		+ len_privateKeyValue;
	len_seq = len_version + len_privateKeyAlgorithm + len_privateKey;

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
		*buf ++ = 0x02;
		*buf ++ = 0x01;
		*buf ++ = 0x00;

		/* privateKeyAlgorithm */
		*buf ++ = 0x30;
		*buf ++ = (sizeof OID_SPHINCSPUBKEY);
		memcpy(buf, OID_SPHINCSPUBKEY, sizeof OID_SPHINCSPUBKEY);
		buf += sizeof OID_SPHINCSPUBKEY;

		/* privateKey */
		*buf ++ = 0x04;
		buf += br_asn1_encode_length(buf, len_privateKeyValue);
		br_encode_sphincs_p_raw_der(buf, sk, pk);

		return 1 + lenlen + len_seq;
	}
}
