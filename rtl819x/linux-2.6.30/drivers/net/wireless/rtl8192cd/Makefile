#
# drivers/net/rtl8192cd
#
# Makefile for the Linux Wireless network device drivers.
#

ifeq ($(CONFIG_RTL_92D_SUPPORT),y)
  ifeq ($(CONFIG_RTL_DUAL_PCIESLOT_BIWLAN_D),y)
  RTL_WLAN_DATA_DIR := data
  endif
  RTL_WLAN_DATA_DIR_D := data_92d
else
  RTL_WLAN_DATA_DIR := data
#  RTL_WLAN_DATA_DIR_D := data_92d
endif

SRCS_TXT = $(addprefix $(src)/data_,$(notdir $(patsubst %.txt,%.c,$(wildcard $(src)/$(RTL_WLAN_DATA_DIR)/*.txt))))
SRCS_BIN = $(addprefix $(src)/data_,$(notdir $(patsubst %.bin,%.c,$(wildcard $(src)/$(RTL_WLAN_DATA_DIR)/*.bin))))
SRCS_TXT += $(addprefix $(src)/data_,$(notdir $(patsubst %.txt,%.c,$(wildcard $(src)/$(RTL_WLAN_DATA_DIR_D)/*.txt))))
SRCS_BIN += $(addprefix $(src)/data_,$(notdir $(patsubst %.bin,%.c,$(wildcard $(src)/$(RTL_WLAN_DATA_DIR_D)/*.bin))))



obj-$(CONFIG_RTL_WAPI_SUPPORT) += wapi_wai.o wapiCrypto.o
obj-$(CONFIG_RTL8192CD) += rtl8192cd.o

rtl8192cd-objs +=\
	8192cd_tx.o\
	8192cd_rx.o\
	8192cd_osdep.o\
	8192cd_sme.o\
	8192cd_util.o\
	8192d_hw.o\
	8192cd_hw.o\
	8192cd_security.o\
	8192cd_tkip.o\
	8192cd_aes.o\
	8192cd_proc.o\
	8192cd_br_ext.o\
	8192cd_eeprom.o\
	8192cd_mp.o\
	8192cd_psk.o\
	8192cd_ioctl.o\
	1x_kmsm_aes.o\
	1x_kmsm_hmac.o\
	1x_md5c.o\
	1x_rc4.o\
	8192cd_mib.o\
	8192cd_dmem.o\
	romeperf.o
ifeq ($(CONFIG_RTL_COMAPI_CFGFILE),y)
obj-y += 8192cd_comapi.o
endif
ifeq ($(CONFIG_RTL_P2P_SUPPORT),y)	
obj-y += 8192cd_p2p.o
endif
ifeq ($(CONFIG_RTL_COMAPI_WLTOOLS),y)
obj-y += 8192cd_comapi.o
endif
#For Hostapd
ifeq ($(CONFIG_RTL_HOSTAPD_SUPPORT),y)
obj-y += 8192cd_comapi.o
obj-y += 8192cd_net80211.o
obj-y += 8192cd_psk_hapd.o
endif

EXTRA_CFLAGS += -I$(DIR_BOARD) 
#EXTRA_CFLAGS += -I$(DIR_BOARD) -Werror
#EXTRA_CFLAGS += -I$(DIR_LINUX)/drivers/net/rtl819x/

#
#Build C code for TXT or BIN file
#
$(obj)/8192cd_hw.o :  $(SRCS_TXT) $(SRCS_BIN)

$(obj)/data_%.c: $(src)/$(RTL_WLAN_DATA_DIR)/%.txt FORCE
	$(obj)/bin2c.pl $(notdir $(basename $@)) < $< > $@
$(obj)/data_%.c: $(src)/$(RTL_WLAN_DATA_DIR)/%.bin FORCE
	$(obj)/bin2c.pl $(notdir $(basename $@)) < $< > $@
$(obj)/data_%.c: $(src)/$(RTL_WLAN_DATA_DIR_D)/%.txt FORCE
	$(obj)/bin2c.pl $(notdir $(basename $@)) < $< > $@
$(obj)/data_%.c: $(src)/$(RTL_WLAN_DATA_DIR_D)/%.bin FORCE
	$(obj)/bin2c.pl $(notdir $(basename $@)) < $< > $@
