#
# Realtek Semiconductor Corp.
#
# Tony Wu (tonywu@realtek.com)
# Dec. 07, 2008
#

DIR_ROOT ?= ..
DIR_BOARD ?= $(DIR_ROOT)/target

.EXPORT_ALL_VARIABLES:
.PHONY: all romfs clean prune

ifneq (.config,$(wildcard .config))
all: config
else
all: lib app

include .config
include $(DIR_ROOT)/.config
include $(DIR_LINUX)/.config

CONFIG_RTL_WAPI_LOCAL_AS=0

# 8198 and POCKET ROUTER support both wapi psk and wapi cert
# 8196C (not include POCKET ROUTER) only support wapi psk
ifdef CONFIG_RTL_8198_GW
ifdef CONFIG_RTL_WAPI_SUPPORT
ifdef CONFIG_RTL_WAPI_LOCAL_AS_SUPPORT
CONFIG_RTL_WAPI_LOCAL_AS=1
endif
CONFIG_APP_OPENSSL=y
CONFIG_APP_WAPI=y
endif
else # !CONFIG_RTL_8198_GW

ifdef CONFIG_POCKET_ROUTER_SUPPORT
ifdef CONFIG_RTL_WAPI_SUPPORT
ifdef CONFIG_RTL_WAPI_LOCAL_AS_SUPPORT
CONFIG_RTL_WAPI_LOCAL_AS=1
endif
# ############################################
# Because rootfs + 64K wapi-cert is oversize at 2M/16M,
# close WAN apps here just for wapi logo test!!!!!!
CONFIG_APP_PPPD=n
CONFIG_APP_PPTP=n
CONFIG_APP_L2TPD=n
CONFIG_APP_NTPCLIENT=n
CONFIG_APP_DNRD=n
CONFIG_APP_IPROUTE=n
# ############################################
CONFIG_APP_OPENSSL=y
CONFIG_APP_WAPI=y
endif
endif

endif

ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
CONFIG_APP_OPENSSL=y
CONFIG_RTL_WAPI_LOCAL_AS=1
endif

ifdef CONFIG_RTL_COMAPI_WLTOOLS
WLTOOLS=wireless_tools.29
else
WLTOOLS=wireless_tools.25
endif

#EXIST=$(wildcard $(DIR_RSDK)/bin/rsdk-uclibc-gcc)
#ifneq ($(EXIST),)
#CROSS_COMPILE ?= rsdk-uclibc-
#else
CROSS_COMPILE ?= rsdk-linux-
#endif

CC = $(CROSS_COMPILE)gcc
CXX = $(CROSS_COMPILE)g++
LD = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
RANLIB = $(CROSS_COMPILE)ranlib
STRIP = $(CROSS_COMPILE)strip
SSTRIP = $(CROSS_COMPILE)sstrip

ifeq ($(CONFIG_RSDK_rsdk-1.5.0-4181-EB-2.6.30-0.9.30.2),y)
CFLAGS += -mips16
endif
ifeq ($(CONFIG_RSDK_rsdk-1.5.0-4181-EB-2.6.30-0.9.30.3),y)
CFLAGS += -mips16
endif
CFLAGS += -I$(DIR_TMPFS)/include

CINIT=1

app_y = 
app_n =
app_  =

lib_y = 
lib_n =
lib_  =

export CFLAGS

# library
ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
lib_$(CONFIG_APP_OPENSSL)		+= openssl-0.9.8b
endif

lib_y += shared #mars add
#lib_y += goahead-2.1.1 #Edison add
lib_y += httpd #Edison add

# application
app_$(CONFIG_APP_BUSYBOX)		+= busybox
#app_$(CONFIG_APP_GOAHEAD)		+= goahead-2.1.1
ifeq ($(CINIT), 1)
app_$(CONFIG_APP_SCRIPT)		+= script/cinit
else
app_$(CONFIG_APP_SCRIPT)		+= script
endif
app_$(CONFIG_APP_SQUASHFS40)		+= squashfs4.0/squashfs-tools
app_$(CONFIG_APP_IPROUTE)		+= iproute2-2.6.29-1
app_$(CONFIG_APP_IPTABLES)		+= iptables-1.4.4
app_$(CONFIG_APP_NTPCLIENT)		+= ntpclient
app_$(CONFIG_APP_DHCPV6)		+= wide-dhcpv6
app_$(CONFIG_APP_RADVD)			+= radvd-0.9.1
app_$(CONFIG_APP_GDBSERVER)             += gdb
app_$(CONFIG_APP_USBMOUNT)		+= usbmount
app_$(CONFIG_APP_DOSFSCK)		+= dosfstools-2.11/dosfsck
app_$(CONFIG_APP_MKDOSFS)		+= dosfstools-2.11/mkdosfs
app_$(CONFIG_APP_NTFS3G)		+= ntfs-3g-2010.10.2
app_$(CONFIG_APP_MP)			+= mp-daemon
app_$(CONFIG_APP_SAMBA)			+= samba-3.0.24/source
app_$(CONFIG_APP_GPROXY)		+= gproxy
app_$(CONFIG_APP_IGMPPROXY)		+= igmpproxy
app_$(CONFIG_APP_PATHSEL)		+= 11s-PathSelection
app_$(CONFIG_APP_WIRELESSTOOLS)		+= $(WLTOOLS)
app_$(CONFIG_APP_DNRD)			+= dnrd-2.12.1/src
app_$(CONFIG_APP_ROUTED)		+= routed
app_$(CONFIG_APP_PPPD)			+= ppp-2.4.4/pppd
app_$(CONFIG_APP_PPTP)			+= pptp-1.7.2
app_$(CONFIG_APP_L2TPD)			+= l2tpd
app_$(CONFIG_APP_DNSMASQ)		+= dnsmasq-2.33
app_$(CONFIG_APP_MINI_UPNP)		+= mini_upnp
app_$(CONFIG_APP_WSC)			+= wsc 
app_$(CONFIG_APP_AUTH)			+= auth/src 
app_$(CONFIG_APP_IWCONTROL)		+= auth/src/dlisten
app_$(CONFIG_APP_HOSTAPD)		+= hostapd-0.6.9/hostapd
app_$(CONFIG_APP_UDHCPD)		+= udhcp-0.9.9-pre
app_$(CONFIG_APP_BRCTL)			+= bridge-utils
app_$(CONFIG_APP_MINIIGD)		+= miniigd
app_$(CONFIG_APP_RELOAD)		+= rc
app_$(CONFIG_APP_LLTDD)			+= lltdd/native-linux
app_$(CONFIG_APP_ORAYDDNS)			+= orayddns
app_$(CONFIG_APP_UPDATEDD)			+=  updatedd-2.5
app_$(CONFIG_APP_DISCOVER)			+=  discover
app_$(CONFIG_APP_IAPP)			+= IAPP 
app_$(CONFIG_APP_NFBI)			+= nfbi
app_$(CONFIG_APP_HOSTAPD_SLAVE)			+= hostapd_slave
app_$(CONFIG_APP_CTORRENT)              += ctorrent-dnh3.3.2
app_$(CONFIG_APP_DCTS)			+= dctcs.src/src
app_y += httpd shared #mars add
app_y += nvram #mars add
app_y		+= wanduck	#Added by Jerry
app_y += www #Added by Jerry-2010/03/03
app_y += ate #Added by Edison 2011.3.25
app_y += atewatchdog #Added by Edison 2011.03.25
app_y		+= tcpcheck	#2010.03.14 Jerry
app_y		+= macclone	#2011.03.16 Jerry
app_y		+= fwupgrade	#2011.04.27 Jerry
app_y += infosvr #Added by Edison 2011.5.4
app_y += notify_service #2011.06.17 Jerry
app_y += detectWAN #2011.07.04 Jerry
app_y += pppoe-relay #2011.07.11 Emily

# USB3G
app_$(CONFIG_APP_COMGT)			+= comgt.0.32
app_$(CONFIG_APP_CHAT)			+= ppp-2.4.4/chat
app_$(CONFIG_APP_LIBUSB)		+= libusb-0.1.12
app_$(CONFIG_APP_USBMODESWITCH)		+= usb-modeswitch
app_$(CONFIG_APP_MBPK_EJECT)		+= mbpk_eject
app_$(CONFIG_APP_USBMODESWITCH_DATA)	+= usb-modeswitch-data
app_$(CONFIG_APP_USBUTILS)		+= usbutils-0.86
app_$(CONFIG_APP_HUBCTRL)		+= hub-ctrl
app_$(CONFIG_APP_MNET)		        += mnet

# debug & test
app_$(CONFIG_APP_CLE_SHELL)		+= cle-shell
app_$(CONFIG_APP_UTILS)			+= utils
app_$(CONFIG_APP_IPERF)			+= iperf-2.0.4
app_$(CONFIG_APP_DHRYSTONE)		+= dhrystone
app_$(CONFIG_APP_IOZONE)		+= iozone3_327/src/current
app_$(CONFIG_APP_LTP)			+= ltp

# wapi related
lib_$(CONFIG_APP_OPENSSL)		+= openssl-0.9.8b

lib_$(CONFIG_APP_HOSTAPD_HCM)		+= inband_lib
lib_$(CONFIG_APP_HOSTAPD_SLAVE)		+= inband_lib
app_$(CONFIG_APP_WAPI)			+= wapi_utils/udp_sock wapi_utils/rwWapiFiles \
					  wapi_utils/other_tools wapi_utils/wapi_scripts
app_$(CONFIG_APP_HOSTAPD_HCM)           += hostapd-0.6.10/hostapd inband_lib
app_$(CONFIG_APP_DLNA_DMS)		+= dlna_dms
#lib_$(CONFIG_LIBNL) += iw-0.9.17
lib_$(CONFIG_LIB_NL) += libnl-1.1
# libraries
lib_$(CONFIG_APP_FLEX)			+= flex-2.5.33
lib_$(CONFIG_APP_PPPD)			+= ppp-2.4.4/pppd/plugins/rp-pppoe

lib:
ifneq ($(lib_y),)
	#$(MAKE) $(sort $(lib_y)) || exit $$?
	$(MAKE) $(lib_y) || exit $$?
else
	@echo "No libs specified"
endif
app:
	$(MAKE) $(sort $(app_y)) || exit $$?
endif
#
# add directory dependancies here
#
.PHONY: ulibs romfs $(sort $(lib_y)) $(sort $(app_y))

# We create the target directory of the symlink if it does
# not exist so the test in check-symlink works and we have a
# directory for generated filesas used by some architectures.
define create-symlink
	if [ ! -L cle-shell ]; then                                      \
			echo '  SYMLINK cle-shell -> ../../../ICTest/users/cle-shell/'; \
			ln -fsn ../../../ICTest/users/cle-shell/ cle-shell;                         \
	fi
endef

prepare:
ifeq ($(CONFIG_APP_CLE_SHELL),y)
	@$(create-symlink)
endif
ifeq ($(CONFIG_APP_UTILS),y)
	@if [ ! -L utils ]; then \
			echo '  SYMLINK utils -> ../../../ICTest/users/utils/'; \
			ln -fsn ../../../ICTest/users/utils/ utils; \
	fi
endif
ifeq ($(CONFIG_APP_IPERF),y)
	@if [ ! -e ./iperf-2.0.4/Makefile ]; then \
		cd ./iperf-2.0.4; \
		ac_cv_func_malloc_0_nonnull=yes ./configure --host=mips-linux --disable-threads --disable-web100; \
	fi
endif
ifeq ($(CONFIG_APP_OPENSSL),y)
	cd ./openssl-0.9.8b; \
	if [ $(CONFIG_RTL_WAPI_LOCAL_AS) = 1 ]; then \
		if [ ! -f dlib_config_done ]; then \
			./Configure shared rsdk-linux; make depend; \
			rm -f slib_config_done; touch dlib_config_done; \
			make clean; \
			cp Makefile.DLibForWapi Makefile; \
			cp test/Makefile.wapi test/Makefile; \
			fi;\
	else\
		if [ ! -f slib_config_done ]; then \
			./Configure no-threads no-hw no-shared rsdk-linux; make depend; \
			rm -f dlib_config_done; touch slib_config_done;\
			make clean; \
			cp Makefile.SLibForWapi Makefile; \
			cp test/Makefile.wapi test/Makefile; \
		fi;\
	fi;\
	cd -;
endif

ifeq ($(CONFIG_APP_IPTABLES),y)
	@cd ./iptables-1.4.4; \
	if [ ! -f iptables_config_done ]; then \
		./configure --host=mips-linux --with-ksource=../../linux-2.6.30 --enable-static --disable-shared --disable-ipv6 CFLAGS=-Os; make depend; \
		rm -f iptables_config_done; touch iptables_config_done; \
		cp Makefile.RSDK Makefile; \
		cp ./extensions/GNUmakefile.RSDK ./extensions/GNUmakefile; \
	fi; \
	cd -
endif

ifeq ($(CONFIG_APP_GDBSERVER),y)
	echo 'make gdbserver';
	cd ./gdb; \
	if [ ! -f gdb_config_done ]; then \
		cd gdb-6.8; ./configure --target=mips-linux --host=i686-pc-linux-gnu --prefix=$(shell pwd)/gdb/gdb-host;  \
		cp Makefile.RSDK Makefile; \
		cd gdb/gdbserver; \
		./configure --target=mips-linux --host=mips-linux --prefix=$(shell pwd)/gdb/gdbserver-6.8; \
		cd ../../../; \
		rm -f gdb_config_done; touch gdb_config_done; \
	fi; \
	cd ..
endif

ifeq ($(CONFIG_HTTP_FILE_SERVER_SUPPORT), y)
	cp goahead-2.1.1/http_files.obj goahead-2.1.1/http_files.o
	cp goahead-2.1.1/LINUX/fmhttp_files_gw.obj goahead-2.1.1/LINUX/fmhttp_files_gw.o
endif

$(sort $(lib_y)): prepare
	[ ! -d "$@" ] || $(MAKE) -C $@ || exit $$?

$(sort $(app_y)): prepare
	[ ! -d "$@" ] || $(MAKE) -C $@ || exit $$?

#%_only:
#	$(MAKE) -C $(@:_only=)
#
#%_clean:
#	$(MAKE) -C $(@:_clean=) clean; true
#
#%_romfs:
#	$(MAKE) -C $(@:_romfs=) romfs

ulibs:
	[ -e $(DIR_ROMFS)/lib ] || mkdir -p $(DIR_ROMFS)/lib
	for i in $(sort $(lib_y)) ; do \
		[ ! -d $$i ] || $(MAKE) -C $$i romfs || exit $$? ; \
	done

romfs:
	[ -e $(DIR_ROMFS)/bin ] || mkdir -p $(DIR_ROMFS)/bin
	for i in $(sort $(app_y)) ; do \
		[ ! -d $$i ] || $(MAKE) -C $$i romfs || exit $$? ; \
	done

clean:
	-for i in $(sort $(app_y) $(app_n) $(app_)) ; do \
		$(MAKE) -C $$i clean ; \
	done

prune:
	-for i in $(sort $(app_n) $(app_)) ; do \
		found=0; \
		for j in $(sort $(app_y)) ; do \
			if [ $$i = $$j ]; then \
				found=1; \
			fi; \
		done; \
	done

include Kconfig.mk
