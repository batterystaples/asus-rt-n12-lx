#
# Realtek Semiconductor Corp.
#
# Makefile -- Build instructions for Realtek RLXOCP with initramfs
#
# Tony Wu (tonywu@realtek.com.tw)
# Dec. 12, 2007
#

VERSION = RTL8196C v1.0
#DIRS = bin dev etc home lib mnt proc usr var sys tmp
DIRS = bin dev etc home lib mnt proc usr var sys 

.PHONY: romfs image

include $(DIR_LINUX)/.config
include $(DIR_ROOT)/.config 
include $(DIR_USERS)/.config 
#include $(DIR_USERS)/goahead-2.1.1/LINUX/svn_version.h
#2011.05.14 Jerry {
include $(DIR_USERS)/httpd/LINUX/svn_version.h
#2011.05.14 Jerry }

MAKE_DEV_NODE = 0
#MGBIN = $(DIR_USERS)/goahead-2.1.1/LINUX/mgbin
#2011.05.14 Jerry {
MGBIN = $(DIR_USERS)/httpd/LINUX/mgbin
#2011.05.14 Jerry }

#FW_BIN = image/fw.bin
FW_VER = `./extract_ver.sh`
FW_BIN = image/$(MODEL_NAME)_$(FW_VER).trx

FW_NOWEB_BIN = image/fw_noweb.bin

ROOT_BIN = image/root.bin

LINUX_BIN  = image/linux.bin

ifdef CONFIG_RTL_WEBPAGES_IN_ROOTFS
WEBPAGE_BIN = 
else
WEBPAGE_BIN = image/webpages-gw.bin
endif

ifdef CONFIG_APP_USBMOUNT
MAKE_DEV_NODE = 1
endif

romfs:
	rm -rf $(DIR_ROMFS)
	[ -d $(DIR_ROMFS)/$$i ] || mkdir -p $(DIR_ROMFS)
	for i in $(DIRS); do \
		[ -d $(DIR_ROMFS)/$$i ] || mkdir -p $(DIR_ROMFS)/$$i; \
	done
	mkdir $(DIR_ROMFS)/dev/misc
	#chmod 777 $(DIR_ROMFS)/tmp
	$(ROMFSINST) etc /etc
ifndef CONFIG_RTL_8196C_iNIC
	rm $(DIR_ROMFS)/etc/smb.conf.bak 
endif
	$(ROMFSINST) -s /var/ppp /etc/ppp
	#$(ROMFSINST) home /home	#Commented by Jerry-2011/1/20
	$(ROMFSINST) -s bin/init /init
ifdef CONFIG_RTL_WEBPAGES_IN_ROOTFS
	#cp $(DIR_USERS)/goahead-2.1.1/LINUX/webpages-gw.gz ./
	#tar xvfz webpages-gw.gz
	#mv web-gw $(DIR_ROMFS)/web
	#rm -rf webpages-gw.gz
	#$(ROMFSINST) -s /var/config.dat /web/config.dat
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
	$(DIR_TOOLS)/mkimg USERS_DIR="$(DIR_USERS)" LINUX_DIR="$(DIR_LINUX)" TOOLS_DIR="$(DIR_TOOLS)" TOOLCHAIN_DIR="$(DIR_RSDK)" USE_SAMBA=$(MAKE_DEV_NODE) || exit $$?
	$(MAKE) -C $(DIR_LINUX)/rtkload
	cp $(DIR_LINUX)/vmlinux $(DIR_IMAGE)/vmlinux.elf
	cp $(DIR_LINUX)/rtkload/linux.bin $(DIR_IMAGE)/linux.bin
	cp $(DIR_LINUX)/rtkload/nfjrom $(DIR_IMAGE)/nfjrom 
ifndef CONFIG_RTL_8196C_iNIC
	@egrep "^CONFIG_MODEL_RTL8196C_MP=y" $(DIR_ROOT)/.config > MP.test; \
	if [ -s MP.test ] ; then \
		echo "It it MP image"; \
	else \
		[ ! -f root.bin ] || cp -f root.bin $(DIR_IMAGE)/root.bin; \
		egrep "^CONFIG_APP_GOAHEAD=y" $(DIR_USERS)/.config > GOAHEAD.test; \
		if [ -s GOAHEAD.test ] ; then \
			$(MGBIN) -c -o $(FW_BIN) $(ROOT_BIN) $(LINUX_BIN); \
			cd $(DIR_USERS)/httpd/LINUX; \
			#mv *.dat ../../../boards/rtl8196c/image; \
			cd -; \
		fi; \
	fi; \
	rm *.test
else
	[ ! -f root.bin ] || cp -f root.bin $(DIR_IMAGE)/root.bin; \
	$(MGBIN) -c -o $(FW_NOWEB_BIN) $(ROOT_BIN) $(LINUX_BIN); 
endif

