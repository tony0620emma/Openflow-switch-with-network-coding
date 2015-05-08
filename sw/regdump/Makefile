#
# $Id: Makefile 2397 2007-10-11 21:06:08Z grg $
#

CFLAGS = -g
CC = gcc
LDFLAGS = -lncurses

all : regdump

regdump : regdump.o ../../../../lib/C/common/nf2util.o ../../../../lib/C/common/nf2util_proxy_common.o

clean :
	rm -f regdump *.o

install:

.PHONY: all clean install
