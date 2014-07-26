CRYPTLIB = portingssl
WSCSRC = src

all: wscd-tmp.conf
	make -C $(CRYPTLIB)

	@echo "" > ./.diff_config; 

	@if [ -e .kernel_config ]; then \
		diff .kernel_config ../../linux-2.6.30/.config > .diff_config; \
		if [ -s .diff_config ]; then \
		        cp ../../linux-2.6.30/.config .kernel_config; \
			make -C $(WSCSRC) clean; \
                fi; \
        else \
                cp ../../linux-2.6.30/.config ./.kernel_config; \
	fi;

	make -C $(WSCSRC)
	
clean:
	make -C $(CRYPTLIB) clean
	make -C $(WSCSRC) clean

wscd-tmp.conf: $(WSCSRC)/wscd.conf
	egrep '*' $^ | sed -e 's,<#ZVMODELVZ#>,$(MODEL_NAME),g' -e 's,\r,,' > $@

romfs:
	$(ROMFSINST) $(WSCSRC)/wscd /bin/wscd
	#$(ROMFSINST) $(WSCSRC)/wscd.conf /etc/wscd.conf
	$(ROMFSINST) wscd-tmp.conf /etc/wscd.conf
	rm -rf wscd-tmp.conf
