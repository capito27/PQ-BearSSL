# PQ-BearSSL

Implemented the quantum resistant public key and signature algorithms *Crystals-Kyber* and *Crystals-Dilithium* in the BearSSL TLS library.

## About this project

This project constitutes my Bachelor's project for Information Security within the University of Applied Sciences of Western Switzerland.

This project was completed throughout February 2020 to July 2020.

## Motivations

The goal of this project is to observe the feasability of implementing quantum resistant cryptography in modern Internet security systems and protocols. 

It was chosen to implement it in a TLS 1.2 library.

For details about the decision process to select this specific TLS version, library, Quantum Resistant algorithm and analysis of other existing solutions (i.e. Open Quantum Safe), please refer to the associated report.

## Build instructions

Ensure that all usual BearSSL build dependencies are met, and then simply run `make` in the BearSSL directory
 
## Test instructions

Initial automated testing for *Kyber* and *Dilithium* speed and x509 can be run as built in the `build` directory.

### Crypto tests

However, due to way with which the official test vectors for Kyber and Dilithium were computed not being available in BearSSL, the crypto accuracy testing for them is quite different.

In the `kyber` and `dilithium` folders lies the reference implementations of both algorithms.
In the `params.h` header of both implementations, one can find macro definitions to both pin the output of the internal RNG functions, as well as supporting code to print the contents of the function outputs (keys, signatures, ciphertexts and shared secrets).
In the `BearSSL/inc/bearssl_kyber.h` `and BearSSL/inc/bearssl_dilithium.h` headers, similar macros can be found, having the same effects on the RNG function.

Once all 3 projects (BearSSL, kyber and dilithium) compiled with the crypto testing support, one can simply run the kyber `test_kex_xxx` file, dilithium `test_dilithium` file or BearSSL `testspeed` file with the appropriate algorithm, and simply use the output from those tests in a diff check to verify the accuracy of the implementations.

### SSL tests

Fisrt of all, one can find at the root of the BearSSL directory a python3 script that takes an existing certificate, and is able to insert a given dilithium public key inside, as well as resign it using a given private key.
The script also supports the creation of mixed certificate chains, that is, a Dilithium certificate signed with ECDSA or RSA PKCS1.
However, the script does not support, by design, the creation of mixed certificates using a Dilithium signature to certific an EC or RSA public key.

One can find a slew of Dilithium signed test certificates and associated private keys inside of the `dilithium_test_certificates` and `dilithium_test_keys` directories.

One is able to build the sample Dilithium client/server without user authentication with the following commands, assuming that the BearSSL library was built prior:

```
# Sample server build instructions 
gcc samples/server_basic.c -Os -Iinc/ -Lbuild/ -l:libbearssl.a -o server_basic

# Sample client build instructions 
gcc samples/client_basic.c -Os -Iinc/ -Lbuild/ -l:libbearssl.a -o client_basic
``` 

To launch the sample client/servers, one can run the following commands :

```
./server_basic 4443
./client_basic localhost 4443
```

NB : Due to the embedded certificates, the client MUST target the localhost SNI.

To be able to test more advanced server configurations, one can use the `brssl` utility as follows:

```
# brssl server start
./build/brssl server \
			-cert samples/cert-ee-dilithium.pem \
			-key  samples/key-ee-dilithium.pem \
            -CA   samples/cert-ica-ec.pem \
            -serverpref \
            -noreneg \
			-b 0.0.0.0 \
			-p 4443

# The cert and key param are self expanatory, they are the server's certificate chain, along with the server's end entity private key.
# The CA param is an optional param, used to specify the server's trust anchors, and enable client authentication.

# brssl client start
./build/brssl client \
			127.0.0.1:4443 \
			-sni localhost \
			-CA samples/cert-ica-dilithium.pem \
			-cert samples/cert-ee-dilithium+ec.pem \
			-key samples/key-ee-dilithium.pem \
			-nostaticecdh \
			-noreneg

# The sni param will override the expected value from the server's certificate. for the provided certificates, it is either "localhost" or "www.example.com"
# The CA param is used to specify the client's trust anchors for the server certificate validation.
# The optional cert and key params are used for client authentication.
```

One can also use the `brssl` utility to generate a dilithium keypair