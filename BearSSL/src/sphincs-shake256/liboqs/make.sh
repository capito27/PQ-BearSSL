#!/bin/bash

cd "$(dirname "$0")"
rm -rf build && mkdir build && cd build

cmake -GNinja -DOQS_MINIMAL_BUILD="OQS_ENABLE_SIG_sphincs_shake256_128f_robust;OQS_ENABLE_SIG_sphincs_shake256_128f_simple;OQS_ENABLE_SIG_sphincs_shake256_128s_robust;OQS_ENABLE_SIG_sphincs_shake256_128s_simple;OQS_ENABLE_SIG_sphincs_shake256_192f_robust;OQS_ENABLE_SIG_sphincs_shake256_192f_simple;OQS_ENABLE_SIG_sphincs_shake256_192s_robust;OQS_ENABLE_SIG_sphincs_shake256_192s_simple;OQS_ENABLE_SIG_sphincs_shake256_256f_robust;OQS_ENABLE_SIG_sphincs_shake256_256f_simple;OQS_ENABLE_SIG_sphincs_shake256_256s_robust;OQS_ENABLE_SIG_sphincs_shake256_256s_simple" -DOQS_BUILD_ONLY_LIB="ON" -DCMAKE_BUILD_TYPE="Release" -DOQS_DIST_BUILD="ON" -DOQS_USE_OPENSSL="OFF" ..
ninja

cd lib

#ar -x liboqs.a

