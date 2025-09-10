APPLICATION = validation-test

BOARD ?= nucleo-l552ze-q

RIOTBASE ?= $(CURDIR)/../..

DEVELHELP ?= 1

QUIET ?= 1

TOOLCHAIN = llvm
WERROR = 0

USEMODULE += log log_color xtimer mpu_prog
CFLAGS += -v -O2 -DLOG_LEVEL=LOG_ALL

include $(RIOTBASE)/Makefile.include
