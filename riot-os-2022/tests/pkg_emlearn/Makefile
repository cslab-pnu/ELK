#include ../Makefile.tests_common
APPLICATION = wolfssl-test
BOARD ?= nucleo-l552ze-q

RIOTBASE ?= $(CURDIR)/../..

DEVELHELP ?= 1

QUIET ?= 1

TOOLCHAIN = llvm
WERROR = 0

USEMODULE += log log_color xtimer
CFLAGS += -O2 -DLOG_LEVEL=LOG_ALL
USEPKG += emlearn

BLOBS += digit

BUILDDEPS += model.h

include $(RIOTBASE)/Makefile.include

model.h: $(CURDIR)/model
	$(Q)$(CURDIR)/generate_model.py
	$(Q)echo "/* fix for no newline at eof */" >> model.h
