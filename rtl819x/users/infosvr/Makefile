#
# milli_httpd Makefile
#
# Copyright (C) 2001 Broadcom Corporation
#
# $Id: Makefile,v 1.3 2011/07/18 03:45:25 edison_shih Exp $
#
#CFLAGS	+= -I. -I$(TOP)/shared -I$(SRCBASE)/include -Wall -I. -Wall -Dlinux $(GLOBAL_OPTIONS)
 
#CFLAGS	+= -g -DDEBUG
#CFLAGS	+= -s -O2 -DNO_PARALLEL
#LDFLAGS	+= -L$(TOP)/nvram -L$(TOP)/shared -L$(TOP)/netconf -lnvram -lshared -lnetconf

#vpath %.c $(TOP)/shared

#USERDIR = $(ROOTDIR)/user
DIR_USERS = $(DIR_ROOT)/users
DIR_HTTP = $(DIR_ROOT)/users/httpd


#CFLAGS  += -I. -I$(DIR_USERS)/shared/include -I$(DIR_HTTP)/include -I$(DIR_ROOT)/linux-2.6.30/include -Wall
CFLAGS  += -I. -I$(DIR_USERS)/shared/include -I$(DIR_HTTP)/include -I../httpd/LINUX -I$(DIR_ROOT)/linux-2.6.30/include -Wall
#CFLAGS  += -Dlinux -DASUS_NVRAM -DNO_PARALLEL -DPRNINFO
CFLAGS  += -Dlinux -DASUS_NVRAM -DMODEL_NAME=\"$(MODEL_NAME)\"
#LDFLAGS = -L$(DIR_USERS)/shared -L$(DIR_USERS)/netconf -lshared -lnetconf

LDFLAGS = -L../httpd/LINUX -lapmib

all: infosvr

clean:
	rm -f *.o *~ infosvr

install: all
# Neo
#	install -d $(INSTALLDIR)/usr/sbin
#	install httpd $(INSTALLDIR)/usr/sbin
#	$(STRIP) $(INSTALLDIR)/usr/sbin/httpd

	install -d $(INSTALLDIR)/bin
	$(STRIP) infosvr
	install infosvr $(INSTALLDIR)/bin

romfs:
	$(ROMFSINST) /bin/infosvr
#infosvr: ./infosvr.o ./common.o ./packet.o ./service.o ./interface.o ./storage.o #./wlutils.o
infosvr: ./infosvr.o ./common.o #./packet.o  #./interface.o #./storage.o #./service.o #./wlutils.o
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)
	$(STRIP) $@

