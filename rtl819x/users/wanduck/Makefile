OBJS = wanduck.o
BIN = wanduck
TOP = $(DIR_ROOT)/users

CFLAGS  += -I. -I$(TOP)/shared -I$(TOP)/shared/include -I$(DIR_ROOT)/linux-2.6.30/include -I../httpd/LINUX
#CFLAGS  += -I. -I$(SRCBASE)/include -I$(TOP)/shared -I$(TOP)/shared/include -I$(DIR_ROOT)/linux-2.6.30/include 
#-I$(ROOTDIR)/linux-2.6.21.x/drivers/net/raeth
CFLAGS  += -Wall -s -O2 -DASUS_NVRAM 

LDFLAGS += -L$(TOP)/shared -L../httpd/LINUX -lshared -s -lapmib

all: ${BIN}
	${STRIP} ${BIN}

#install: all
#	install -D ${BIN} ${INSTALLDIR}/usr/sbin/${BIN}
romfs:
	$(ROMFSINST) ${BIN} /bin/${BIN}


${BIN}: ${OBJS}
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f *.o ${BIN}
