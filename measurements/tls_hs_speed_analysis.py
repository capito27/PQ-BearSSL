#!/usr/bin/env python3
# This script will generate statistics regarding the TLS handhsakes taking place inside of a packet capture file.

import pyshark
from statistics import mean, stdev
import sys


if len(sys.argv) < 2:
    print("Error, must provide packet capture containing the handshakes to get statistics from!")
    quit(1)

client_hellos = pyshark.FileCapture(sys.argv[1], display_filter='tls.handshake.type==1')

change_cipher_specs = pyshark.FileCapture(sys.argv[1], display_filter='tls.record.content_type==20')

cipher_suites = pyshark.FileCapture(sys.argv[1], display_filter='tls.handshake.type==2')

PQ_timing = []
classical_timings = []

ctr = 1
# Process all the TLS handshakes
try:
    while True:
        if ctr %100 == 0:
            print(f"{Progress : ctr}")
        change_cipher_specs.next() # Drop the first change cipher spec packet of the handshake, since it's not the end of the handshake yet
        if cipher_suites.next()["tls"].get("handshake_ciphersuite") == '57024': # if the given handhsake used the quantum cipher suite
            PQ_timing.append(float(change_cipher_specs.next().sniff_timestamp) - float(client_hellos.next().sniff_timestamp))
        else:
            classical_timings.append(float(change_cipher_specs.next().sniff_timestamp) - float(client_hellos.next().sniff_timestamp))

except StopIteration:
    pass

if PQ_timing:
    print(f"Quantum resistant handshake duration stats\nAverage : {mean(PQ_timing) * 1000} ms, standard deviation : {stdev(PQ_timing) * 1000} ms, number of samples : {len(PQ_timing)}")

if classical_timings:
    print(f"Traditional handshake duration stats\nAverage : {mean(classical_timings) * 1000} ms, standard deviation : {stdev(classical_timings) * 1000} ms, number of samples : {len(classical_timings)}")
