
# Realtek Semiconductor Corp.
#
# Makefile -- Build instructions for Realtek RLXOCP with initramfs
#
# Tony Wu (tonywu@realtek.com.tw)
# Dec. 12, 2007
#

VERSION = RTL8198 v1.0
#DIRS = bin dev etc home lib mnt proc usr var sys tmp
DIRS = bin dev etc home lib mnt proc usr var sys 

.PHONY: romfs image

include $(DIR_LINUX)/.config
include $(DIR_ROOT)/.config 
include $(DIR_USERS)/.config 
include $(DIR_USERS)/goahead-2.1.1/LINUX/svn_version.h

MGBIN = $(DIR_USERS)/goahead-2.1.1/LINUX/mgbin

FW_BIN = image/fw.bin

FW_NOWEB_BIN = image/fw_noweb.bin

ROOT_BIN = image/root.bin

LINUX_BIN  = image/linux.bin

ifdef CONFIG_RTL_WEBPAGES_IN_ROOTFS
WEBPAGE_BIN = 
ifdef CONFIG_RTL_8198_AP_ROOT
WEBIMAGE_GZ = webpages-ap.gz
WEB_NAME = web-ap
else	#!CONFIG_RTL_8198_AP_ROOT
WEBIMAGE_GZ = webpages-gw.gz
WEB_NAME = web-gw
endif	#CONFIG_RTL_8198_AP_ROOT
else	#!CONFIG_RTL_WEBPAGES_IN_ROOTFS
ifdef CONFIG_RTL_8198_AP_ROOT
WEBPAGE_BIN = image/webpages-ap.bin
WEBIMAGE_BIN = webpages-ap.bin
else	#!CONFIG_RTL_8198_AP_ROOT
WEBPAGE_BIN = image/webpages-gw.bin
WEBIMAGE_BIN = webpages-gw.bin
endif	#CONFIG_RTL_8198_AP_ROOT
endif	#CONFIG_RTL_WEBPAGES_IN_ROOTFS

romfs:
	rm -rf $(DIR_ROMFS)
	[ -d $(DIR_ROMFS)/$$i ] || mkdir -p $(DIR_ROMFS)
	for i in $(DIRS); do \
		[ -d $(DIR_ROMFS)/$$i ] || mkdir -p $(DIR_ROMFS)/$$i; \
	done
	mkdir $(DIR_ROMFS)/dev/misc
	#chmod 777 $(DIR_ROMFS)/tmp
	$(ROMFSINST) etc /etc
	rm -f $(DIR_ROMFS)/etc/smb.conf.bak

	$(ROMFSINST) -s /var/ppp /etc/ppp
	$(ROMFSINST) home /home
	$(ROMFSINST) -s bin/init /init
ifdef CONFIG_RTL_WEBPAGES_IN_ROOTFS
	cp $(DIR_USERS)/goahead-2.1.1/LINUX/$(WEBIMAGE_GZ) ./ 
	tar xvfz $(WEBIMAGE_GZ)
	mv $(WEB_NAME) $(DIR_ROMFS)/web
	rm -rf $(WEBIMAGE_GZ)
	$(ROMFSINST) -s /var/config.dat /web/config.dat
else
	$(ROMFSINST) -s /var/web /web
endif
	$(ROMFSINST) -s /var/tmp /tmp
	chmod 755 $(DIR_ROMFS)/etc/init.d/rcS
ifdef CONFIG_RTL_WEBPAGES_IN_ROOTFS
	sed -i "s/flash extr \/web/#flash extr \/web/" $(DIR_ROMFS)/etc/init.d/rcS
endif
ifeq ($(CONFIG_RTL8192CD),m)
	sed -i "14i insmod /lib/modules/2.6.30.9/kernel/drivers/net/wireless/rtl8192cd/rtl8192cd.ko" $(DIR_ROMFS)/etc/init.d/rcS
endif
	echo "$(VERSION) -- " `date` > $(DIR_ROMFS)/etc/version
	echo "The SDK version is:         $(CURRENT_VERSION)" >> $(DIR_ROMFS)/etc/version
	echo "Ethernet driver version is: $(NIC_DRIVER_VERSION)" >> $(DIR_ROMFS)/etc/version
	echo "Wireless driver version is: $(WLAN_DRIVER_VERSION)" >> $(DIR_ROMFS)/etc/version
	echo "Fastpath source version is: $(FASTPATH_VERSION)" >> $(DIR_ROMFS)/etc/version

image:
	[ -d $(DIR_IMAGE) ] || mkdir -p $(DIR_IMAGE)
	rm -rf $(DIR_IMAGE)/*
	$(DIR_TOOLS)/mkimg USERS_DIR="$(DIR_USERS)" LINUX_DIR="$(DIR_LINUX)" TOOLS_DIR="$(DIR_TOOLS)" TOOLCHAIN_DIR="$(DIR_RSDK)" USE_SAMBA=1 || exit $$?
	$(MAKE) -C $(DIR_LINUX)/rtkload
	cp $(DIR_LINUX)/vmlinux $(DIR_IMAGE)/vmlinux.elf
	cp $(DIR_LINUX)/rtkload/linux.bin $(DIR_IMAGE)/linux.bin
	cp $(DIR_LINUX)/rtkload/nfjrom $(DIR_IMAGE)/nfjrom
ifdef CONFIG_RTL_8198_INBAND_AP
	[ ! -f root.bin ] || cp -f root.bin $(DIR_IMAGE)/root.bin; \
	$(MGBIN) -c -o $(FW_NOWEB_BIN) $(ROOT_BIN) $(LINUX_BIN);
else
	@egrep "^CONFIG_MODEL_RTL8198_MP=y" $(DIR_ROOT)/.config > MP.test; \
	if [ -s MP.test ] ; then \
		echo "It it MP image"; \
	else \
		[ ! -f root.bin ] || cp -f root.bin $(DIR_IMAGE)/root.bin; \
		egrep "^CONFIG_APP_GOAHEAD=y" $(DIR_USERS)/.config > GOAHEAD.test; \
		if [ -s GOAHEAD.test ] ; then \
			cp $(DIR_USERS)/goahead-2.1.1/LINUX/$(WEBIMAGE_BIN) $(DIR_IMAGE)/$(WEBIMAGE_BIN); \
			$(MGBIN) -c -o $(FW_BIN) $(ROOT_BIN) $(WEBPAGE_BIN) $(LINUX_BIN); \
			cd $(DIR_USERS)/goahead-2.1.1/LINUX; \
			mv *.dat ../../../boards/rtl8198/image; \
			cd -; \
		fi; \
	fi; \
	rm *.test
endif
