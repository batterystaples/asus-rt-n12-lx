############################################################################
#
# Realtek Semiconductor Corp.
#
# Makefile -- Top level dist makefile.
#
# Tony Wu (tonywu@realtek.com)
# Oct. 12, 2008
#

ifneq (.config,$(wildcard .config))
TARGET := config
#
# DIR_ROOT Used when .config not Exist
#
DIR_ROOT = $(shell pwd)
else

include .config

#
# variables
#

DIR_ROOT = $(shell pwd)
DIR_RSDK = $(DIR_ROOT)/$(CONFIG_RSDKDIR)

DIR_BOARD = $(DIR_ROOT)/target
DIR_ROMFS = $(DIR_ROOT)/target/romfs
DIR_TMPFS = $(DIR_ROOT)/target/tmpfs
DIR_IMAGE = $(DIR_ROOT)/target/image
DIR_TOOLS = $(DIR_ROOT)/target/tools
DIR_USERS = $(DIR_ROOT)/users
DIR_BZBOX = $(DIR_ROOT)/$(CONFIG_BZBOXDIR)
DIR_LINUX = $(DIR_ROOT)/$(CONFIG_LINUXDIR)

ROMFSINST = $(DIR_ROOT)/config/romfsinst

MAKE = PATH=$(DIR_RSDK)/bin:$(PATH); make
LSTRIP = PATH=$(DIR_RSDK)/bin:$(PATH); rsdk-linux-lstrip
SSTRIP = PATH=$(DIR_RSDK)/bin:$(PATH); rsdk-linux-sstrip

export DIR_ROOT DIR_RSDK DIR_ROMFS DIR_IMAGE DIR_BOARD DIR_TMPFS
export DIR_LINUX DIR_BZBOX ROMFSINST DIR_TOOLS DIR_USERS MODEL_NAME

ERROR :=
ifneq ($(CONFIG_BZBOXDIR),$(wildcard $(CONFIG_BZBOXDIR)))
ERROR += '$(CONFIG_BZBOXDIR) does not exist '
endif

ifneq ($(CONFIG_LINUXDIR),$(wildcard $(CONFIG_LINUXDIR)))
ERROR += '$(CONFIG_LINUXDIR) does not exist '
endif

ifneq ($(CONFIG_RSDKDIR),$(wildcard $(CONFIG_RSDKDIR)))
ERROR += '$(CONFIG_RSDKDIR) does not exist'
endif

ifeq ($(ERROR),)
#TARGET := bins romfs modules linux image
#2011.03.22 Jerry {
TARGET := bootloader bins romfs modules linux image
#2011.03.22 Jerry }
else
TARGET := error
endif

#2011.04.14 Jerry {
ifeq ($(MODEL_NAME),)
TARGET := make_error
endif
#2011.04.14 Jerry }

endif

#add for 8198 and 8196c use the different toolchain
TOOLCHAIN =
ifeq ($(CONFIG_BOARD_rtl8198), y)
TOOLCHAIN = 5281
else
TOOLCHAIN = 4181
endif

all: $(TARGET)

error:
	@echo
	@echo "=== NOTICE ===" 
	@echo
	@for X in $(ERROR) ; do \
		echo ERROR: $$X; \
	done
	@echo
	@echo "Please run 'make config' to reconfigure"
	@echo

#2011.04.14 Jerry {
make_error:
	@echo "Please make with MODEL_NAME parameter!!!"
	@echo "For example: make MODEL_NAME=RT-N10LX"
#2011.04.14 Jerry }

#
# 0. target selection
#
.PHONY: config menuconfig
config menuconfig:
	@chmod u+x config/genconfig
	@chmod u+x config/setconfig
	@config/genconfig > Kconfig
	@config/mconf Kconfig
	@config/setconfig defaults
	@if egrep "^CONFIG_MCONF_LINUX=y" .config > /dev/null; then \
		$(MAKE) -C $(DIR_LINUX) menuconfig; \
	fi
	@if egrep "^CONFIG_MCONF_USERS=y" .config > /dev/null; then \
		$(MAKE) -C $(DIR_USERS) menuconfig; \
	fi
	@if egrep "^CONFIG_MCONF_BZBOX=y" .config > /dev/null; then \
		$(MAKE) -C $(DIR_BZBOX) menuconfig; \
	fi
	@config/setconfig final
	@config/hdrconfig $(DIR_ROOT)

#2011.03.22 Jerry {
.PHONY: bootloader
bootloader:
	$(MAKE) -C ../bootcode_rtl8196c_98
#2011.03.22 Jerry }
	
#
# 1. user lib
#
#.PHONY: libs
#libs:
#	$(MAKE) -C $(DIR_USERS) lib || exit $$?

#
# 2. user app
#
.PHONY: users bins
users bins:
	$(MAKE) -C $(DIR_USERS) || exit $$?

#
#2.1 user menuconfig
#
users_menuconfig:
	$(MAKE) -C $(DIR_USERS) menuconfig; 

#
# 3. romfs
#
#	[ -d $(DIR_ROMFS) ] || mkdir $(DIR_ROMFS)
.PHONY: romfs
romfs:
	$(MAKE) -C $(DIR_BOARD) romfs || exit $$?
	cp -R $(DIR_RSDK)/lib/*.so $(DIR_ROMFS)/lib
	cp -R $(DIR_RSDK)/lib/*.so.* $(DIR_ROMFS)/lib
	chmod 755 $(DIR_ROMFS)/lib/*.so
#2011.03.22 Jerry {
	./install_fw_version.sh
#2011.03.22 Jerry }
	$(MAKE) -C $(DIR_USERS) TOOLCHAIN=$(TOOLCHAIN) romfs || exit $$?
	$(LSTRIP) $(DIR_ROMFS)
	cp $(DIR_USERS)/httpd/clear_cache.sh $(DIR_ROMFS)/bin/

#
# 4.0 kernel modules (if any)
#
.PHONY: modules
modules:
	$(MAKE) -C $(DIR_LINUX) modules || exit $$?
	$(MAKE) -C $(DIR_LINUX) modules_install INSTALL_MOD_PATH=$(DIR_ROMFS) || exit $$?

#
# 4.1 kernel image
#
.PHONY: linux
linux:
	. $(DIR_LINUX)/.config; if [ "$$CONFIG_INITRAMFS_SOURCE" != "" ]; then \
        cd $(DIR_LINUX); \
        mkdir -p $(DIR_ROMFS); \
        touch $$CONFIG_INITRAMFS_SOURCE | awk '{print $2}' || exit 1; \
        cd $(DIR_ROOT); \
	fi
	$(MAKE) -C $(DIR_LINUX) || exit $$?
	if [ -f $(DIR_LINUX)/vmlinux ]; then \
        ln -f $(DIR_LINUX)/vmlinux $(DIR_LINUX)/linux ; \
	fi
#
#4.2 kernel menuconfig
#
linux_menuconfig:
	$(MAKE) -C $(DIR_LINUX) menuconfig; 

#
# 5. image
#
.PHONY: image
image:
	sudo find $(DIR_ROMFS)  -type d -name "CVS" | sudo xargs rm -rf
	[ -d $(DIR_IMAGE) ] || mkdir $(DIR_IMAGE)
	$(MAKE) -C $(DIR_BOARD) image
#2011.03.22 Jerry {
	./install_fw_version.sh
	cp ../bootcode_rtl8196c_98/btcode/boot.bin $(DIR_IMAGE)
#2011.03.22 Jerry }

.PHONY: release
release:
	$(MAKE) -C $(DIR_USERS)/goahead-2.1.1/LINUX release

.PHONY: clean
clean:
	$(MAKE) -C $(DIR_USERS) clean
	$(MAKE) -C $(DIR_LINUX) clean
	rm -rf $(DIR_ROMFS)
	mkdir -p $(DIR_ROMFS)
	mkdir -p $(DIR_IMAGE)
