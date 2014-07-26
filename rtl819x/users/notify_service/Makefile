OBJS = notify_service.o
BIN = notify_service

CFLAGS  += -I. -I$(DIR_ROOT)/linux-2.6.30/include #-I$(HTTPD)
CFLAGS  += -Wall -s -O2 

all: ${BIN}
	${STRIP} ${BIN}

romfs:
	$(ROMFSINST) ${BIN} /bin/${BIN}


${BIN}: ${OBJS}
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f *.o ${BIN}
