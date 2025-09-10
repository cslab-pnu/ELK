#include ../Makefile.tests_common
APPLICATION = dtls_wolfssl

# If no BOARD is found in the environment, use this default:
BOARD ?= nucleo-l552ze-q

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..
# This is an optimized stack value based on testing, if you observe
# a segmentation fault please increase this stack size.
CFLAGS += -DTHREAD_STACKSIZE_MAIN=2*THREAD_STACKSIZE_LARGE

USEPKG += wolfssl
USEMODULE += wolfcrypt wolfcrypt-test wolfcrypt_sha512 \
             wolfcrypt_curve25519 wolfcrypt_ed25519 wolfcrypt_chacha \
             wolfcrypt_poly1305 wolfcrypt_aes wolfcrypt_ecc \
             wolfcrypt_asn wolfcrypt_random

# Uncomment the following line to enable RSA tests
# (e.g. when enough resources are available on platform)
USEMODULE += wolfcrypt_rsa wolfcrypt_dh

# Comment the following line to disable full-benchmark test
USEMODULE += wolfcrypt-benchmark

USEMODULE += xtimer

#ifneq ($(BOARD),native)
  #CFLAGS += -DBENCH_EMBEDDED
#endif

#TEST_ON_CI_WHITELIST += native

TOOLCHAIN = llvm
WERROR = 0

USEMODULE += log log_color xtimer mpu_prog
CFLAGS += -O2 -DLOG_LEVEL=LOG_ALL
#CFLAGS += -DELK_PEAK_MEMORY_USAGE
CFLAGS += -DWOLFSSL_SMALL_STACK
CFLAGS += -DBENCH_EMBEDDED

include $(RIOTBASE)/Makefile.include
