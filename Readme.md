# PQ-BearSSL

Implemented the quantum resistant public key and signature algorithms *Crystals-Kyber* and *Crystals-Dilithium* in the BearSSL TLS library.

## About this project

This project constitutes my Bachelor's project for Information Security within the University of Applied Sciences of Western Switzerland.

This project was completed throughout February 2020 to July 2020.

## Motivations

The goal of this project is to observe the feasability of implementing quantum resistant cryptography in modern Internet security systems and protocols. 

It was chosen to implement it in a TLS 1.2 library.

For details about the decision process to select this specific TLS version, library, Quantum Resistant algorithm and analysis of other existing solutions (i.e. Open Quantum Safe), please refer to the report.

## Major Implementation changes

- Reimplemented the reference implementation of Kyber and Dilithium, using the available computation primaries in BearSSL, in as many flavors as possible and feasable.
- Created a custom TLS Extension to the Client Hello handshake message with ID 38, which is currently unassigned, according to this [IANA document](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml).

* Extension of the BearSSL SSL engine architecture to support this additional Extension, as well as supporting the new PMS derivation system, based upon a KEM construction.