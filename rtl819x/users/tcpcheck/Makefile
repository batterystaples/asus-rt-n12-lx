CFLAGS += -g -O2

all: tcpcheck

tcpcheck: tcpcheck.o
	$(CC) tcpcheck.o -o tcpcheck

clean:
	rm -f tcpcheck httpdcheck *~ *.o

romfs:
	$(STRIP) tcpcheck
	cp tcpcheck httpdcheck
	$(ROMFSINST) tcpcheck /bin/tcpcheck
	$(ROMFSINST) httpdcheck /bin/httpdcheck
