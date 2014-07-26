# Generated automatically from Makefile.in by configure.
# Generated automatically from Makefile.in by configure.
#***********************************************************************
#
# Makefile
#
# Makefile for Roaring Penguin's Linux user-space PPPoE client.
#
# Copyright (C) 2000 Roaring Penguin Software Inc.
#
# This program may be distributed according to the terms of the GNU
# General Public License, version 2 or (at your option) any later version.
#
# LIC: GPL
#
# $Id: Makefile,v 1.1 2011/07/13 07:21:31 emily Exp $
#***********************************************************************

# Version is set ONLY IN THE MAKEFILE!  Don't delete this!
VERSION=3.5

OBJS = relay.o debug.o if.o common.o
BIN = pppoe-relay
TOP = $(DIR_ROOT)/users

CFLAGS  += -I. -I$(TOP)/shared -I$(TOP)/shared/include -I$(DIR_ROOT)/linux-2.6.30/include -I../httpd/LINUX
CFLAGS= -s -O2 -I. -DVERSION=3.5

LDFLAGS += -L$(TOP)/shared -L../httpd/LINUX -lshared -s -lapmib

all: ${BIN}
	${STRIP} ${BIN}

romfs:
	$(ROMFSINST) ${BIN} /bin/${BIN}

${BIN}: ${OBJS}
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f *.o ${BIN}
