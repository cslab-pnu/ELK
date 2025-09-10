# name of your application
APPLICATION = aha-compress

# If no BOARD is found in the environment, use this default:
BOARD ?= nucleo-l552ze-q

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../../..

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 0

TOOLCHAIN = llvm
WERROR = 0 

USEMODULE += log log_color xtimer mpu_prog
CFLAGS += -v -O2 -DLOG_LEVEL=LOG_ALL

include $(RIOTBASE)/Makefile.include
