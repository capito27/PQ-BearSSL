// SPDX-License-Identifier: MIT

#define OQS_VERSION_TEXT "0.7.0"
#define OQS_COMPILE_BUILD_TARGET "x86_64-Linux-5.13.15-1-MANJARO"
#define OQS_DIST_BUILD 1
#define OQS_DIST_X86_64_BUILD 1
/* #undef OQS_DIST_X86_BUILD */
/* #undef OQS_DIST_ARM64v8_BUILD */
/* #undef OQS_DIST_ARM32v7_BUILD */
/* #undef OQS_DIST_PPC64LE_BUILD */
/* #undef OQS_DEBUG_BUILD */
#define ARCH_X86_64 1
/* #undef ARCH_ARM64v8 */
/* #undef ARCH_ARM32v7 */

/* #undef OQS_USE_OPENSSL */
/* #undef OQS_USE_AES_OPENSSL */
/* #undef OQS_USE_SHA2_OPENSSL */
/* #undef OQS_USE_SHA3_OPENSSL */

/* #undef OQS_USE_PTHREADS_IN_TESTS */

/* #undef OQS_USE_ADX_INSTRUCTIONS */
/* #undef OQS_USE_AES_INSTRUCTIONS */
/* #undef OQS_USE_AVX_INSTRUCTIONS */
/* #undef OQS_USE_AVX2_INSTRUCTIONS */
/* #undef OQS_USE_AVX512_INSTRUCTIONS */
/* #undef OQS_USE_BMI1_INSTRUCTIONS */
/* #undef OQS_USE_BMI2_INSTRUCTIONS */
/* #undef OQS_USE_PCLMULQDQ_INSTRUCTIONS */
/* #undef OQS_USE_VPCLMULQDQ_INSTRUCTIONS */
/* #undef OQS_USE_POPCNT_INSTRUCTIONS */
/* #undef OQS_USE_SSE_INSTRUCTIONS */
/* #undef OQS_USE_SSE2_INSTRUCTIONS */
/* #undef OQS_USE_SSE3_INSTRUCTIONS */

/* #undef OQS_USE_ARM_AES_INSTRUCTIONS */
/* #undef OQS_USE_ARM_SHA2_INSTRUCTIONS */
/* #undef OQS_USE_ARM_SHA3_INSTRUCTIONS */
/* #undef OQS_USE_ARM_NEON_INSTRUCTIONS */

/* #undef OQS_ENABLE_TEST_CONSTANT_TIME */

#define OQS_ENABLE_SHA3_xkcp_low_avx2 1

/* #undef OQS_ENABLE_KEM_BIKE */
/* #undef OQS_ENABLE_KEM_bike_l1 */
/* #undef OQS_ENABLE_KEM_bike_l3 */

/* #undef OQS_ENABLE_KEM_FRODOKEM */
/* #undef OQS_ENABLE_KEM_frodokem_640_aes */
/* #undef OQS_ENABLE_KEM_frodokem_640_shake */
/* #undef OQS_ENABLE_KEM_frodokem_976_aes */
/* #undef OQS_ENABLE_KEM_frodokem_976_shake */
/* #undef OQS_ENABLE_KEM_frodokem_1344_aes */
/* #undef OQS_ENABLE_KEM_frodokem_1344_shake */

/* #undef OQS_ENABLE_KEM_SIDH */
/* #undef OQS_ENABLE_KEM_sidh_p434 */
/* #undef OQS_ENABLE_KEM_sidh_p434_compressed */
/* #undef OQS_ENABLE_KEM_sidh_p503 */
/* #undef OQS_ENABLE_KEM_sidh_p503_compressed */
/* #undef OQS_ENABLE_KEM_sidh_p610 */
/* #undef OQS_ENABLE_KEM_sidh_p610_compressed */
/* #undef OQS_ENABLE_KEM_sidh_p751 */
/* #undef OQS_ENABLE_KEM_sidh_p751_compressed */

/* #undef OQS_ENABLE_KEM_SIKE */
/* #undef OQS_ENABLE_KEM_sike_p434 */
/* #undef OQS_ENABLE_KEM_sike_p434_compressed */
/* #undef OQS_ENABLE_KEM_sike_p503 */
/* #undef OQS_ENABLE_KEM_sike_p503_compressed */
/* #undef OQS_ENABLE_KEM_sike_p610 */
/* #undef OQS_ENABLE_KEM_sike_p610_compressed */
/* #undef OQS_ENABLE_KEM_sike_p751 */
/* #undef OQS_ENABLE_KEM_sike_p751_compressed */

/* #undef OQS_ENABLE_SIG_PICNIC */
/* #undef OQS_ENABLE_SIG_picnic_L1_UR */
/* #undef OQS_ENABLE_SIG_picnic_L1_FS */
/* #undef OQS_ENABLE_SIG_picnic_L1_full */
/* #undef OQS_ENABLE_SIG_picnic_L3_UR */
/* #undef OQS_ENABLE_SIG_picnic_L3_FS */
/* #undef OQS_ENABLE_SIG_picnic_L3_full */
/* #undef OQS_ENABLE_SIG_picnic_L5_UR */
/* #undef OQS_ENABLE_SIG_picnic_L5_FS */
/* #undef OQS_ENABLE_SIG_picnic_L5_full */
/* #undef OQS_ENABLE_SIG_picnic3_L1 */
/* #undef OQS_ENABLE_SIG_picnic3_L3 */
/* #undef OQS_ENABLE_SIG_picnic3_L5 */

///// OQS_COPY_FROM_UPSTREAM_FRAGMENT_ADD_ALG_ENABLE_DEFINES_START

/* #undef OQS_ENABLE_KEM_CLASSIC_MCELIECE */
/* #undef OQS_ENABLE_KEM_classic_mceliece_348864 */
/* #undef OQS_ENABLE_KEM_classic_mceliece_348864_avx */
/* #undef OQS_ENABLE_KEM_classic_mceliece_348864f */
/* #undef OQS_ENABLE_KEM_classic_mceliece_348864f_avx */
/* #undef OQS_ENABLE_KEM_classic_mceliece_460896 */
/* #undef OQS_ENABLE_KEM_classic_mceliece_460896_avx */
/* #undef OQS_ENABLE_KEM_classic_mceliece_460896f */
/* #undef OQS_ENABLE_KEM_classic_mceliece_460896f_avx */
/* #undef OQS_ENABLE_KEM_classic_mceliece_6688128 */
/* #undef OQS_ENABLE_KEM_classic_mceliece_6688128_avx */
/* #undef OQS_ENABLE_KEM_classic_mceliece_6688128f */
/* #undef OQS_ENABLE_KEM_classic_mceliece_6688128f_avx */
/* #undef OQS_ENABLE_KEM_classic_mceliece_6960119 */
/* #undef OQS_ENABLE_KEM_classic_mceliece_6960119_avx */
/* #undef OQS_ENABLE_KEM_classic_mceliece_6960119f */
/* #undef OQS_ENABLE_KEM_classic_mceliece_6960119f_avx */
/* #undef OQS_ENABLE_KEM_classic_mceliece_8192128 */
/* #undef OQS_ENABLE_KEM_classic_mceliece_8192128_avx */
/* #undef OQS_ENABLE_KEM_classic_mceliece_8192128f */
/* #undef OQS_ENABLE_KEM_classic_mceliece_8192128f_avx */

/* #undef OQS_ENABLE_KEM_HQC */
/* #undef OQS_ENABLE_KEM_hqc_128 */
/* #undef OQS_ENABLE_KEM_hqc_128_avx2 */
/* #undef OQS_ENABLE_KEM_hqc_192 */
/* #undef OQS_ENABLE_KEM_hqc_192_avx2 */
/* #undef OQS_ENABLE_KEM_hqc_256 */
/* #undef OQS_ENABLE_KEM_hqc_256_avx2 */

/* #undef OQS_ENABLE_KEM_KYBER */
/* #undef OQS_ENABLE_KEM_kyber_512 */
/* #undef OQS_ENABLE_KEM_kyber_512_avx2 */
/* #undef OQS_ENABLE_KEM_kyber_768 */
/* #undef OQS_ENABLE_KEM_kyber_768_avx2 */
/* #undef OQS_ENABLE_KEM_kyber_1024 */
/* #undef OQS_ENABLE_KEM_kyber_1024_avx2 */
/* #undef OQS_ENABLE_KEM_kyber_512_90s */
/* #undef OQS_ENABLE_KEM_kyber_512_90s_avx2 */
/* #undef OQS_ENABLE_KEM_kyber_768_90s */
/* #undef OQS_ENABLE_KEM_kyber_768_90s_avx2 */
/* #undef OQS_ENABLE_KEM_kyber_1024_90s */
/* #undef OQS_ENABLE_KEM_kyber_1024_90s_avx2 */

/* #undef OQS_ENABLE_KEM_NTRU */
/* #undef OQS_ENABLE_KEM_ntru_hps2048509 */
/* #undef OQS_ENABLE_KEM_ntru_hps2048509_avx2 */
/* #undef OQS_ENABLE_KEM_ntru_hps2048677 */
/* #undef OQS_ENABLE_KEM_ntru_hps2048677_avx2 */
/* #undef OQS_ENABLE_KEM_ntru_hps4096821 */
/* #undef OQS_ENABLE_KEM_ntru_hps4096821_avx2 */
/* #undef OQS_ENABLE_KEM_ntru_hrss701 */
/* #undef OQS_ENABLE_KEM_ntru_hrss701_avx2 */

/* #undef OQS_ENABLE_KEM_NTRUPRIME */
/* #undef OQS_ENABLE_KEM_ntruprime_ntrulpr653 */
/* #undef OQS_ENABLE_KEM_ntruprime_ntrulpr653_avx2 */
/* #undef OQS_ENABLE_KEM_ntruprime_ntrulpr761 */
/* #undef OQS_ENABLE_KEM_ntruprime_ntrulpr761_avx2 */
/* #undef OQS_ENABLE_KEM_ntruprime_ntrulpr857 */
/* #undef OQS_ENABLE_KEM_ntruprime_ntrulpr857_avx2 */
/* #undef OQS_ENABLE_KEM_ntruprime_sntrup653 */
/* #undef OQS_ENABLE_KEM_ntruprime_sntrup653_avx2 */
/* #undef OQS_ENABLE_KEM_ntruprime_sntrup761 */
/* #undef OQS_ENABLE_KEM_ntruprime_sntrup761_avx2 */
/* #undef OQS_ENABLE_KEM_ntruprime_sntrup857 */
/* #undef OQS_ENABLE_KEM_ntruprime_sntrup857_avx2 */

/* #undef OQS_ENABLE_KEM_SABER */
/* #undef OQS_ENABLE_KEM_saber_lightsaber */
/* #undef OQS_ENABLE_KEM_saber_lightsaber_avx2 */
/* #undef OQS_ENABLE_KEM_saber_saber */
/* #undef OQS_ENABLE_KEM_saber_saber_avx2 */
/* #undef OQS_ENABLE_KEM_saber_firesaber */
/* #undef OQS_ENABLE_KEM_saber_firesaber_avx2 */

/* #undef OQS_ENABLE_SIG_DILITHIUM */
/* #undef OQS_ENABLE_SIG_dilithium_2 */
/* #undef OQS_ENABLE_SIG_dilithium_2_avx2 */
/* #undef OQS_ENABLE_SIG_dilithium_3 */
/* #undef OQS_ENABLE_SIG_dilithium_3_avx2 */
/* #undef OQS_ENABLE_SIG_dilithium_5 */
/* #undef OQS_ENABLE_SIG_dilithium_5_avx2 */
/* #undef OQS_ENABLE_SIG_dilithium_2_aes */
/* #undef OQS_ENABLE_SIG_dilithium_2_aes_avx2 */
/* #undef OQS_ENABLE_SIG_dilithium_3_aes */
/* #undef OQS_ENABLE_SIG_dilithium_3_aes_avx2 */
/* #undef OQS_ENABLE_SIG_dilithium_5_aes */
/* #undef OQS_ENABLE_SIG_dilithium_5_aes_avx2 */

/* #undef OQS_ENABLE_SIG_FALCON */
/* #undef OQS_ENABLE_SIG_falcon_512 */
/* #undef OQS_ENABLE_SIG_falcon_512_avx2 */
/* #undef OQS_ENABLE_SIG_falcon_1024 */
/* #undef OQS_ENABLE_SIG_falcon_1024_avx2 */

/* #undef OQS_ENABLE_SIG_RAINBOW */
/* #undef OQS_ENABLE_SIG_rainbow_I_classic */
/* #undef OQS_ENABLE_SIG_rainbow_I_circumzenithal */
/* #undef OQS_ENABLE_SIG_rainbow_I_compressed */
/* #undef OQS_ENABLE_SIG_rainbow_III_classic */
/* #undef OQS_ENABLE_SIG_rainbow_III_circumzenithal */
/* #undef OQS_ENABLE_SIG_rainbow_III_compressed */
/* #undef OQS_ENABLE_SIG_rainbow_V_classic */
/* #undef OQS_ENABLE_SIG_rainbow_V_circumzenithal */
/* #undef OQS_ENABLE_SIG_rainbow_V_compressed */

#define OQS_ENABLE_SIG_SPHINCS 1
/* #undef OQS_ENABLE_SIG_sphincs_haraka_128f_robust */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_128f_robust_aesni */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_128f_simple */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_128f_simple_aesni */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_128s_robust */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_128s_robust_aesni */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_128s_simple */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_128s_simple_aesni */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_192f_robust */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_192f_robust_aesni */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_192f_simple */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_192f_simple_aesni */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_192s_robust */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_192s_robust_aesni */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_192s_simple */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_192s_simple_aesni */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_256f_robust */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_256f_robust_aesni */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_256f_simple */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_256f_simple_aesni */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_256s_robust */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_256s_robust_aesni */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_256s_simple */
/* #undef OQS_ENABLE_SIG_sphincs_haraka_256s_simple_aesni */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_128f_robust */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_128f_robust_avx2 */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_128f_simple */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_128f_simple_avx2 */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_128s_robust */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_128s_robust_avx2 */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_128s_simple */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_128s_simple_avx2 */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_192f_robust */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_192f_robust_avx2 */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_192f_simple */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_192f_simple_avx2 */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_192s_robust */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_192s_robust_avx2 */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_192s_simple */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_192s_simple_avx2 */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_256f_robust */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_256f_robust_avx2 */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_256f_simple */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_256f_simple_avx2 */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_256s_robust */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_256s_robust_avx2 */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_256s_simple */
/* #undef OQS_ENABLE_SIG_sphincs_sha256_256s_simple_avx2 */
#define OQS_ENABLE_SIG_sphincs_shake256_128f_robust 1
#define OQS_ENABLE_SIG_sphincs_shake256_128f_robust_avx2 1
#define OQS_ENABLE_SIG_sphincs_shake256_128f_simple 1
#define OQS_ENABLE_SIG_sphincs_shake256_128f_simple_avx2 1
#define OQS_ENABLE_SIG_sphincs_shake256_128s_robust 1
#define OQS_ENABLE_SIG_sphincs_shake256_128s_robust_avx2 1
#define OQS_ENABLE_SIG_sphincs_shake256_128s_simple 1
#define OQS_ENABLE_SIG_sphincs_shake256_128s_simple_avx2 1
#define OQS_ENABLE_SIG_sphincs_shake256_192f_robust 1
#define OQS_ENABLE_SIG_sphincs_shake256_192f_robust_avx2 1
#define OQS_ENABLE_SIG_sphincs_shake256_192f_simple 1
#define OQS_ENABLE_SIG_sphincs_shake256_192f_simple_avx2 1
#define OQS_ENABLE_SIG_sphincs_shake256_192s_robust 1
#define OQS_ENABLE_SIG_sphincs_shake256_192s_robust_avx2 1
#define OQS_ENABLE_SIG_sphincs_shake256_192s_simple 1
#define OQS_ENABLE_SIG_sphincs_shake256_192s_simple_avx2 1
#define OQS_ENABLE_SIG_sphincs_shake256_256f_robust 1
#define OQS_ENABLE_SIG_sphincs_shake256_256f_robust_avx2 1
#define OQS_ENABLE_SIG_sphincs_shake256_256f_simple 1
#define OQS_ENABLE_SIG_sphincs_shake256_256f_simple_avx2 1
#define OQS_ENABLE_SIG_sphincs_shake256_256s_robust 1
#define OQS_ENABLE_SIG_sphincs_shake256_256s_robust_avx2 1
#define OQS_ENABLE_SIG_sphincs_shake256_256s_simple 1
#define OQS_ENABLE_SIG_sphincs_shake256_256s_simple_avx2 1
///// OQS_COPY_FROM_UPSTREAM_FRAGMENT_ADD_ALG_ENABLE_DEFINES_END
