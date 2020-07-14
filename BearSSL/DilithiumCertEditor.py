#!/usr/bin/env python3

import binascii
from pyasn1_modules import pem, rfc2459
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import Integer, OctetString, ObjectIdentifier, Null, Sequence, namedtype, BitString
from hashlib import sha1, sha224, sha256, sha384, sha512
import argparse
import subprocess

# Custom, non standard OID, for Dilithium signatures with sha.
# This will insert itself into the 1.2.840.10045.4 OID structure  
# for ECDSA from ANSI X9.62 standard (1998).
# If a better solution is available, I'd love to know about it.
# Also, let's not support SHA1, in an attempt to not shoot 
# oneself in the foot
DilithiumSignAlgoToOID = dict()
DilithiumSignAlgoToOID['dilithium-with-SHA224'] = '1.2.840.10045.4.4.1'
DilithiumSignAlgoToOID['dilithium-with-SHA256'] = '1.2.840.10045.4.4.2'
DilithiumSignAlgoToOID['dilithium-with-SHA384'] = '1.2.840.10045.4.4.3'
DilithiumSignAlgoToOID['dilithium-with-SHA512'] = '1.2.840.10045.4.4.4'

# Custom dictionary mapping a signature algorithm OID to its 
# assocaited hash engine (in an attempt to automate mixed type certificates) and signature type (0 = dilithium, 1 = RSA, 2 = EC)
SignOIDToAlgo= dict()
# Dilithium signature algorithms
SignOIDToAlgo['1.2.840.10045.4.4.1'] = (sha224(), 0) 
SignOIDToAlgo['1.2.840.10045.4.4.2'] = (sha256(), 0) 
SignOIDToAlgo['1.2.840.10045.4.4.3'] = (sha384(), 0) 
SignOIDToAlgo['1.2.840.10045.4.4.4'] = (sha512(), 0) 
# RSA signature algorithms
SignOIDToAlgo['1.2.840.113549.1.1.5']  = (sha1(), 1)
SignOIDToAlgo['1.2.840.113549.1.1.14'] = (sha224(), 1)
SignOIDToAlgo['1.2.840.113549.1.1.11'] = (sha256(), 1)
SignOIDToAlgo['1.2.840.113549.1.1.12'] = (sha384(), 1)
SignOIDToAlgo['1.2.840.113549.1.1.13'] = (sha512(), 1)
# ECDSA signature algorithms
SignOIDToAlgo['1.2.840.10045.4.1']   = (sha1(), 2)
SignOIDToAlgo['1.2.840.10045.4.3.1'] = (sha224(), 2)
SignOIDToAlgo['1.2.840.10045.4.3.2'] = (sha256(), 2)
SignOIDToAlgo['1.2.840.10045.4.3.3'] = (sha384(), 2)
SignOIDToAlgo['1.2.840.10045.4.3.4'] = (sha512(), 2)

# Similarly to above, custom OID for Dilithium key types 
DilithiumOIDKeyDict= dict()
DilithiumOIDKeyDict['id-dilithiumPublicKey'] = '1.2.840.10045.2.2'


# Argument parsing
ap = argparse.ArgumentParser()
ap.add_argument("--cert", required=True, type=str,
   help="Existing (PEM encoded) certificate to modify")
   
ap.add_argument("--pub-key", required=True, type=str, 
   help="PEM file containing the DER Dilithium public key to insert into the certificate")

ap.add_argument("--pub-key-type", required=True, type=str, choices=list(DilithiumOIDKeyDict.keys()),
   help="The type of the public key to insert into the certificate")

ap.add_argument("--ca-priv-key", required=True, type=str, 
   help="PEM file containing the DER raw private key used by the certificate authority to sign the certificate.\
        To self sign the certificate, simply provide the Dilithium private key associated with the public \
        key to insert, as well as enabling the flag \"--ca-priv-key-dilithium\"")
   
ap.add_argument("--sign-algorithm", type=str, choices=list(DilithiumSignAlgoToOID.keys()),
   help="The Dilithium signing algorithm used to sign of the certificate.")

ap.add_argument("--ca-priv-key-dilithium", action="store_true", 
   help="Flag to determine if the certificate is to be signed with dilithium. \
        If not set, the certificate will be resigned using the existing signature algorithm \
        If set, --sign-algorithm MUST be provided")

ap.add_argument("-o","--out-file", type=str,
   help="Optional certificate destination, if missing, the certificate will be displayed on the screen. \
         Otherwise, it will be saved in the file.")
   
args = vars(ap.parse_args())

# check that sign-algorithm is present if ca-priv-key-dilithium is true
if args['ca_priv_key_dilithium'] and 'sign_algorithm' not in args:
    ap.error('The --ca-priv-key-dilithium argument requires --sign-algorithm')

# Load the existing certificate
cert_substrate = pem.readPemFromFile(open(args["cert"], 'r'))
cert = decoder.decode(cert_substrate, asn1Spec=rfc2459.Certificate())[0]

# if ca-priv-key-dilithium is not true, we must check that the signing algorithm in place is known and uses a known hash function, otherwise, we can't do much
if args['ca_priv_key_dilithium'] and str(cert["tbsCertificate"]["signature"]["algorithm"]) not in SignOIDToAlgo:
    ap.error("The provided certificate, which is not to be signed with Dilithium, is signed with an unknown algorithm")


# if the certificate was already signed with dilithium, we can simply toggle the flag
if str(cert["tbsCertificate"]["signature"]["algorithm"]) in DilithiumSignAlgoToOID.values():
    args['ca_priv_key_dilithium'] = True
    # if the --sign-algorithm value is not present, set it to the current algorithm
    if 'sign_algorithm' not in args:
        args['sign_algorithm'] = list(DilithiumSignAlgoToOID.keys())[list(DilithiumSignAlgoToOID.values()).index(str(cert["tbsCertificate"]["signature"]["algorithm"]))]


# change TBS signature algorithm if an algorithm is given
if args['sign_algorithm']:
    cert["tbsCertificate"]["signature"]["algorithm"] = ObjectIdentifier(DilithiumSignAlgoToOID[args['sign_algorithm']])

# change TBS public key type
cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"] = ObjectIdentifier(DilithiumOIDKeyDict[args["pub_key_type"]])

# Force Null TBS public key params (in case of EC certificate mainly)
cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["parameters"] = Null("")

# Load the raw DER Dilithium public key from the PEM file
dilithium_substrate = b''
for line in open(args['pub_key'], 'r').readlines():
    if not line.startswith('-'):
        dilithium_substrate += line.rstrip().encode()
dilithium_public_key = decoder.decode(binascii.a2b_base64(dilithium_substrate))[0]['field-2']

# Replace the existing public key with the new Dilithium public key
cert["tbsCertificate"]["subjectPublicKeyInfo"]["subjectPublicKey"] = dilithium_public_key

# Derivate the TBS hash according to the relevant signature algorithm
tbs_der = encoder.encode(cert["tbsCertificate"])

# Get the relevant hash function and signature function from the signature algorithm
hash, sigAlg = SignOIDToAlgo [str(cert["tbsCertificate"]["signature"]["algorithm"])]
hash.update(tbs_der)
final_hash = hash.digest()

# digest algorithm is provided to ensure that the input data is of proper length, 
# but openssl will NOT hash the data prior to signing it, 
# also set the RSA padding mode to pksc#1
cmd = ['openssl', 'pkeyutl', '-sign', '-inkey', args['ca_priv_key'], '-pkeyopt', f'digest:{hash.name}', '-pkeyopt', 'rsa_padding_mode:pkcs1']
newSignature = b""
if sigAlg == 0 : # Dilithium Signature > call to helper C program
    # Open a pipe to send both the DER private key and the hash, as well as get back the signature without going through the filesystem
    # We send the key size through the first argument, so that the key can be distinguished from the data to be signed
    pipe = subprocess.Popen(['./DilithiumCertEditor_dilithium_sign', str(len(binascii.a2b_base64(dilithium_substrate)))], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
    newSignature = pipe.communicate(input=binascii.a2b_base64(dilithium_substrate) + final_hash)[0]

    # Verify the signature was properly generated, if not, print the error
    if pipe.returncode != 0:
        print(newSignature.decode())
        exit(-1)

    # Update the signature algorithm with the one placed inside of the TBS
    cert["signatureAlgorithm"]["algorithm"] = cert["tbsCertificate"]["signature"]["algorithm"]

    # Load the signature into the certificate as a bitstring
    cert["signatureValue"] = BitString.fromOctetString(newSignature)

elif sigAlg == 1: # RSA Signature > openssl call
    # Open a pipe to send the hash and get back the signature without going through the filesystem
    pipe = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
    newSignature = pipe.communicate(input=final_hash)[0]

    # Verify the signature was properly generated, if not, print the error
    if pipe.returncode != 0:
        print(newSignature.decode())
        exit(-1)
    
    # Update the signature algorithm with the one placed inside of the TBS
    cert["signatureAlgorithm"]["algorithm"] = cert["tbsCertificate"]["signature"]["algorithm"]
    # Load the signature into the certificate as a bitstring
    cert["signatureValue"] = BitString.fromOctetString(newSignature)
    
elif sigAlg == 2: # ECDSA Signature > openssl call
    # Open a pipe to send the hash and get back the signature without going through the filesystem, 
    # drop the last 2 arguments, since ECDSA signatures don't use pkcs1 padding
    pipe = subprocess.Popen(cmd[:-2], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
    newSignature = pipe.communicate(input=final_hash)[0]

    # Verify the signature was properly generated, if not, print the error
    if pipe.returncode != 0:
        print(newSignature.decode())
        exit(-1)
        
    # Update the signature algorithm with the one placed inside of the TBS
    cert["signatureAlgorithm"]["algorithm"] = cert["tbsCertificate"]["signature"]["algorithm"]

    # Load the signature into the certificate as a bitstring
    cert["signatureValue"] = BitString.fromOctetString(newSignature)

else :
    print("Something that shouldn't happen did happen, operation aborted")

# save the final spliced certificate
der_encoded = binascii.b2a_base64(encoder.encode(cert))

pem_file = b'-----BEGIN CERTIFICATE-----'
for i in range(0, len(der_encoded), 76):
    pem_file += b'\n'+  der_encoded[i:i+76]

pem_file += b'-----END CERTIFICATE-----\n'

if 'out_file' in args:
    open(args['out_file'], 'wb').write(pem_file)
print(pem_file.decode())