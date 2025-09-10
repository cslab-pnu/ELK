APPLICATION = wasm-example
# If no BOARD is defined in the environment, use this default:
BOARD ?= nucleo-l552ze-q

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

USEPKG += wamr

ifneq ($(BOARD),native)
CFLAGS += -DTHREAD_STACKSIZE_MAIN='(6 * 1024)'
endif

export WAMR_CONFIG := $(abspath config.cmake)

BLOBS += test.wasm hello.wasm

USEMODULE += log log_color xtimer mpu_prog
CFLAGS += -v -O2 -DLOG_LEVEL=LOG_ALL

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

TOOLCHAIN = llvm
WERROR = 0

USEMODULE += mpu_prog log log_color
CFLAGS = -O2 -DLOG_LEVEL=LOG_ALL
CFLAGS += -DTHREAD_STACKSIZE_MAIN='(6 * 1024)'
#CFLAGS += -DBH_ENABLE_GC_VERIFY
#CFLAGS += -DELK_PEAK_MEMORY_USAGE
#LINKFLAGS += -Wl,-wrap=malloc -Wl,-wrap=free

all: hello.wasm

hello.wasm: wasm_sample/hello.c wasm_sample/Makefile
	make -C wasm_sample hello.wasm
	mv wasm_sample/hello.wasm .

#######################################################
# Load the rest of the usual RIOT make infrastructure #
#######################################################

include $(RIOTBASE)/Makefile.include
