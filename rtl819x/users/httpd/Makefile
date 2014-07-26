#
# milli_httpd Makefile
#
# Copyright (C) 2001 ASUSTek Inc.
#
# $Id: Makefile,v 1.6 2011/07/08 09:15:23 emily Exp $
#

#.PHONY: all clean sym_link install romfs gen_syms

SHDIR = $(DIR_ROOT)/users/shared
USERDIR = $(DIR_ROOT)/users

CFLAGS	+= -I. -I$(SHDIR)/include -I$(SHDIR) -I$(DIR_ROOT)/linux-2.6.30/include -I./LINUX

#2008.10 magic add -DWSC
CFLAGS	+= -s -Wall -DASUS_NVRAM -DASUS_DDNS -DTRANSLATE_ON_FLY -DFLASH_EMULATOR -DLinux -DMIPS -DWSC -DRalink_WPS $(GLOBAL_OPTIONS) -DCONFIG_APMIB_SHARED
CFLAGS  += -DHOME_GATEWAY -DMODEL_NAME=\"$(MODEL_NAME)\"
LDFLAGS	= -L$(SHDIR) -L./LINUX -lapmib -lshared

#vpath %.o $(ROOTDIR)/user/shared #2008.10 magic
vpath %.o $(DIR_ROOT)/user/shared #Modified by Jerry-2011/01/21

#ifeq ($(CONFIG_NOUSB),y)	#Comment by Jerry-2011/01/21
CFLAGS += -DNOUSB
#endif	#Comment by Jerry-2011/01/21

LINUX_ARCH = LINUX
DIR_WLAN = $(DIR_LINUX)/drivers/net/wireless/rtl8192cd

ifeq ($(LANGUAGE),KR)
LANG_FILE = EN.dict KR.dict
else
LANG_FILE = EN.dict TW.dict CN.dict 
endif

#2008.10 magic{
#ifeq ($(MODEL_NAME), WL520GU)
#WWWDIR  = ../www/web_asus_en/WL520gu_text
WWWDIR = ../www/www_N56U  #Viz changed 2010.08 
#else
#WWWDIR = ../www/web_asus_en/WL500gp_text
#LANG_FILE += KR.dict
#endif

#vpath translate_%.txt $(WWWDIR)/
vpath %.dict $(WWWDIR)/
#2008.10 magic}

all: sys httpd 
	$(STRIP) httpd

sys:
	@echo "" > ./.diff_config; 

	@if [ -e .kernel_config ]; then \
		diff .kernel_config $(DIR_LINUX)/.config > .diff_config; \
		if [ -s .diff_config ]; then \
		        cp $(DIR_LINUX)/.config .kernel_config; \
			make -C $(LINUX_ARCH) clean; \
                fi; \
        else \
                cp $(DIR_LINUX)/.config ./.kernel_config; \
	fi;

	@echo "" > ./.diff_wlan_mib;
	@if [ -e .wlan_mib_h ]; then \
		diff .wlan_mib_h $(DIR_WLAN)/ieee802_mib.h > .diff_wlan_mib; \
		if [ -s .diff_wlan_mib ]; then \
			cp $(DIR_WLAN)/ieee802_mib.h .wlan_mib_h; \
			make -C $(LINUX_ARCH) clean; \
		fi; \
	else \
		cp $(DIR_WLAN)/ieee802_mib.h ./.wlan_mib_h; \
	fi;

	make -C $(LINUX_ARCH)

dep:
	@echo "Generate depend file..."
	@for i in `find . -name "*.c"`; do ${CC} -MM ${CFLAGS} "$${i}"; done > $@

clean:
	rm -f *.o *~ httpd
	for f in $(LANG_FILE) ; do rm -f $$f; done
	rm -f *.dict
	make -C LINUX clean #add by mars

#%.dict: translate_%.txt #2008.10 magic
%.dict: %.dict #2008.10 magic
	egrep '[^=]*=[^=]*' $^ | sed -e 's,<#ZVMODELVZ#>,$(MODEL_NAME),g' -e 's,\r,,' > $@

romfs:
	make -C $(LINUX_ARCH) romfs
	$(ROMFSINST) httpd /bin/httpd

./LINUX/fmtcpip_gw.o:
	make fmtcpip_gw.o -C LINUX

./LINUX/utility_gw.o:
	make utility_gw.o -C LINUX

./LINUX/fmfwall_gw.o:
	make fmfwall_gw.o -C LINUX

./LINUX/fmget_gw.o:
	make fmget_gw.o -C LINUX

./LINUX/fmwlan_gw.o:
	make fmwlan_gw.o -C LINUX

./LINUX/fmmgmt_gw.o:
	make fmmgmt_gw.o -C LINUX

./LINUX/version_gw.o:
	make version_gw.o -C LINUX

./LINUX/fmddns_gw.o:
	make fmddns_gw.o -C LINUX

./LINUX/fmroute_gw.o:
	make fmroute_gw.o -C LINUX

./LINUX/fmipv6_gw.o:
	make fmipv6_gw.o -C LINUX

#./LINUX/fmbt_gw.o:
#	make fmbt_gw.o -C LINUX

#./LINUX/fmpocketap_gw.o:
#	make fmpocketap_gw.o -C LINUX

# 2008.10 magic. add notify_rc.o & discover.o & initial_web_hook.o
# Viz add aspbw.o 2010.08
#httpd: httpd.o discover.o ej.o cgi.o web_ex.o common.o nvram_f.o initial_web_hook.o aspbw.o ./LINUX/fmtcpip_gw.o ./LINUX/utility_gw.o ./LINUX/utility_gw.o ./LINUX/fmget_gw.o ./LINUX/fmfwall_gw.o ./LINUX/fmwlan_gw.o ./LINUX/fmmgmt_gw.o ./LINUX/version_gw.o ./LINUX/fmddns_gw.o ./LINUX/fmroute_gw.o ./LINUX/fmipv6_gw.o ./LINUX/fmbt_gw.o ./LINUX/fmpocketap_gw.o
httpd: httpd.o discover.o ej.o cgi.o web_ex.o common.o initial_web_hook.o aspbw.o ./LINUX/fmtcpip_gw.o ./LINUX/utility_gw.o ./LINUX/utility_gw.o ./LINUX/fmget_gw.o ./LINUX/fmfwall_gw.o ./LINUX/fmwlan_gw.o ./LINUX/fmmgmt_gw.o ./LINUX/version_gw.o ./LINUX/fmddns_gw.o ./LINUX/fmroute_gw.o ./LINUX/fmipv6_gw.o
	echo $(LANGUAGE)
	#echo $(MODEL_NAME)
	#$(CC) -o $@ $^ $(LDFLAGS) -lshared -lnetconf
	$(CC) -o $@ $^ $(LDFLAGS)
	$(STRIP) $@

