#!/usr/bin/env python3

import binascii

from pyasn1_modules import pem, rfc2459
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import Integer, OctetString, ObjectIdentifier, Null, Sequence, namedtype, BitString
from hashlib import sha1, sha224, sha256, sha384, sha512
import argparse
import subprocess
from os import path

# Custom, non standard OID, for Sphincs signatures with sha.
# This will insert itself into the 1.2.840.10045.4 OID structure  
# for ECDSA from ANSI X9.62 standard (1998).
# If a better solution is available, I'd love to know about it.
# Also, let's not support SHA1, in an attempt to not shoot 
# oneself in the foot
SphincsSignAlgoToOID = dict()
SphincsSignAlgoToOID['sphincs-with-SHA224'] = '1.2.840.10045.4.4.1'
SphincsSignAlgoToOID['sphincs-with-SHA256'] = '1.2.840.10045.4.4.2'
SphincsSignAlgoToOID['sphincs-with-SHA384'] = '1.2.840.10045.4.4.3'
SphincsSignAlgoToOID['sphincs-with-SHA512'] = '1.2.840.10045.4.4.4'

# Custom dictionary mapping a signature algorithm OID to its 
# assocaited hash engine (in an attempt to automate mixed type certificates) and signature type (0 = sphincs, 1 = RSA, 2 = EC)
SignOIDToAlgo= dict()
# Sphincs signature algorithms
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

# Similarly to above, custom OID for Sphincs key types 
SphincsOIDKeyDict= dict()
SphincsOIDKeyDict['id-sphincsPublicKey'] = '1.2.840.10045.2.2'


# Argument parsing
ap = argparse.ArgumentParser()
ap.add_argument("--cert", required=True, type=str,
   help="Existing (PEM or DER encoded) certificate to modify")
   
ap.add_argument("--pub-key", required=True, type=str, 
   help="PEM file containing the DER Sphincs public key to insert into the certificate")

ap.add_argument("--pub-key-type", required=True, type=str, choices=list(SphincsOIDKeyDict.keys()),
   help="The type of the public key to insert into the certificate")

ap.add_argument("--ca-priv-key", required=True, type=str, 
   help="PEM file containing the DER raw private key used by the certificate authority to sign the certificate.\
        To self sign the certificate, simply provide the Sphincs private key associated with the public \
        key to insert, as well as enabling the flag \"--ca-priv-key-sphincs\"")
   
ap.add_argument("--sign-algorithm", type=str, choices=list(SphincsSignAlgoToOID.keys()),
   help="The Sphincs signing algorithm used to sign of the certificate.")

ap.add_argument("--ca-priv-key-sphincs", action="store_true", 
   help="Flag to determine if the certificate is to be signed with sphincs. \
        If not set, the certificate will be resigned using the existing signature algorithm \
        If set, --sign-algorithm MUST be provided")

ap.add_argument("-o","--out-file", type=str,
   help="Optional certificate destination, if missing, the certificate will be displayed on the screen. \
         Otherwise, it will be saved in the file.")
   
args = vars(ap.parse_args())

# check that sign-algorithm is present if ca-priv-key-sphincs is true
if args['ca_priv_key_sphincs'] and not args['sign_algorithm']:
    ap.error('The --ca-priv-key-sphincs argument requires --sign-algorithm')

# Load the existing certificate
ftype = None
f = open(args["cert"], 'rb')
cert_substrate = None
if f.read(27) == b'-----BEGIN CERTIFICATE-----' : # PEM handling
    cert_substrate = pem.readPemFromFile(open(args["cert"], 'r'))
    ftype = 0
else: # DER default
    f.seek(0)
    cert_substrate = f.read()
    ftype = 1
cert = decoder.decode(cert_substrate, asn1Spec=rfc2459.Certificate())[0]
f.close()

# if ca-priv-key-sphincs is not true, we must check that the signing algorithm in place is known and uses a known hash function, otherwise, we can't do much
if args['ca_priv_key_sphincs'] and str(cert["tbsCertificate"]["signature"]["algorithm"]) not in SignOIDToAlgo:
    ap.error("The provided certificate, which is not to be signed with Sphincs, is signed with an unknown algorithm")


# if the certificate was already signed with sphincs, we can simply toggle the flag
if str(cert["tbsCertificate"]["signature"]["algorithm"]) in SphincsSignAlgoToOID.values():
    args['ca_priv_key_sphincs'] = True
    # if the --sign-algorithm value is not present, set it to the current algorithm
    if not args['sign_algorithm']:
        args['sign_algorithm'] = list(SphincsSignAlgoToOID.keys())[list(SphincsSignAlgoToOID.values()).index(str(cert["tbsCertificate"]["signature"]["algorithm"]))]

# If we're supposed to sign with sphincs, check that the helper executable exists in the current directory
if args['ca_priv_key_sphincs'] and not path.exists("SphincsCertEditor_sphincs_sign"):
    print("When attempting to sign with sphincs, could not locate the signing helper.")
    print("It can be compiled as follows : ")
    print("1. Build the BearSSL library")
    print("2. Compile and link the helper binary with the following command : ")
    print("gcc SphincsCertEditor_sphincs_sign.c -Iinc/ -Lbuild/ -l:libbearssl.a -o SphincsCertEditor_sphincs_sign")
    print("NB : The command assumes the current directory to be the root of the BearSSL git structure.")
    exit(-1)

# change TBS signature algorithm if an algorithm is given
if args['sign_algorithm']:
    cert["tbsCertificate"]["signature"]["algorithm"] = ObjectIdentifier(SphincsSignAlgoToOID[args['sign_algorithm']])

# change TBS public key type
cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"] = ObjectIdentifier(SphincsOIDKeyDict[args["pub_key_type"]])

# Force Null TBS public key params (in case of EC certificate mainly)
cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["parameters"] = Null("")

# Load the raw DER Sphincs public key from the PEM file
sphincs_substrate = b''
for line in open(args['pub_key'], 'r').readlines():
    if not line.startswith('-'):
        sphincs_substrate += line.rstrip().encode()
sphincs_public_key = decoder.decode(binascii.a2b_base64(sphincs_substrate))[0]['field-2']

# Replace the existing public key with the new Sphincs public key
cert["tbsCertificate"]["subjectPublicKeyInfo"]["subjectPublicKey"] = sphincs_public_key

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
if sigAlg == 0 : # Sphincs Signature > call to helper C program
    # Load and decode the private key manually
    sphincs_substrate = b''
    for line in open(args['ca_priv_key'], 'r').readlines():
        if not line.startswith('-'):
            sphincs_substrate += line.rstrip().encode()

    # Open a pipe to send both the DER private key and the hash, as well as get back the signature without going through the filesystem
    # We send the key size through the first argument, so that the key can be distinguished from the data to be signed
    pipe = subprocess.Popen(['./SphincsCertEditor_sphincs_sign', str(len(binascii.a2b_base64(sphincs_substrate)))], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
    newSignature = pipe.communicate(input=binascii.a2b_base64(sphincs_substrate) + final_hash)[0]

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

output = b''
if ftype == 0 : # PEM output
    b64_cert = binascii.b2a_base64(encoder.encode(cert))
    output = b'-----BEGIN CERTIFICATE-----'
    for i in range(0, len(b64_cert), 76):
        output += b'\n'+  b64_cert[i:i+76]
    output += b'-----END CERTIFICATE-----\n' 
    if not args['out_file']:
        print(output.decode())
else : # DER output
    output = encoder.encode(cert)
    if not args['out_file']:
        print(output.decode('utf-8', 'ignore'))

if args['out_file']:
    open(args['out_file'], 'wb').write(output)