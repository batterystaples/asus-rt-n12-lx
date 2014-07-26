#
# ATE Makefile
#

DIR_USERS = $(DIR_ROOT)/users
INSTALLDIR = $(DIR_ROOT)/romfs
ROMFSINST = $(DIR_ROOT)/config/romfsinst
SHDIR = $(DIR_ROOT)/users/shared

CFLAGS  += -I$(DIR_ROOT)/linux-2.6.30/include -Wall
#-I$(DIR_ROOT)/linux-2.6.30/include/linux 
#CFLAGS	+= -DWIFI_SIMPLE_CONFIG
 
#LDFLAGS	= -L../goahead-2.1.1/LINUX -L$(SHDIR) -lapmib -lshared

all: atewatchdog

clean:
	rm -f *.o *~ atewatchdog

install: all


	install -d $(INSTALLDIR)/bin
	$(STRIP) atewatchdog
	install atewatchdog $(INSTALLDIR)/bin

romfs:
	$(ROMFSINST) atewatchdog /bin/atewatchdog

ate: atewatchdog.o
	$(CC) -o $@ $^ $(CFLAGS)
	$(STRIP) $@


