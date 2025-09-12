APPLICATION = df-test

BOARD ?= nucleo-l552ze-q

RIOTBASE ?= $(CURDIR)/../../riot-os-2022

DEVELHELP ?= 1

QUIET ?= 1

TOOLCHAIN = llvm
WERROR = 0

USEMODULE += log log_color mpu_prog
CFLAGS += -O2 -DLOG_LEVEL=LOG_ALL

include $(RIOTBASE)/Makefile.include