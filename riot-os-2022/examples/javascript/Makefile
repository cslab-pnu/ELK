# application name
APPLICATION = riot_javascript

# default BOARD environment
BOARD ?= nucleo-l552ze-q

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

ifneq ($(BOARD),native)
# Set stack size to something (conservatively) enormous
CFLAGS += -DTHREAD_STACKSIZE_MAIN=9092
endif

# Add the package for Jerryscript
USEPKG += jerryscript

# generate .js.h header files of .js files
BLOBS += $(wildcard *.js)

TOOLCHAIN = llvm
WERROR = 0

USEMODULE += mpu_prog
CFLAGS += -v -O2

include $(RIOTBASE)/Makefile.include
