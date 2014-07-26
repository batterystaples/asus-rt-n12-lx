OBJS = fwupgrade.o
BIN = fwupgrade
HTTPD = $(DIR_ROOT)/users/httpd/LINUX
#TOP = $(DIR_ROOT)/users

CFLAGS  += -I. -I$(HTTPD)
CFLAGS  += -Wall -s -O2 

LDFLAGS += -L$(HTTPD) -lapmib

all: ${BIN}
	${STRIP} ${BIN}

romfs:
	$(ROMFSINST) ${BIN} /bin/${BIN}


${BIN}: ${OBJS}
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f *.o ${BIN}
