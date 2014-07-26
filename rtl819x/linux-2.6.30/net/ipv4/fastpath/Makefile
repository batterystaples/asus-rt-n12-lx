#
# Makefile for the fastpath modules on top of IPv4.
#

#EXTRA_CFLAGS += -I $(DIR_LINUX)/drivers/net/rtl819x
EXTRA_CFLAGS += -I $(DIR_LINUX)/net
EXTRA_CFLAGS += -D__KERNEL__

include $(DIR_ROOT)/.config

ifeq ($(CONFIG_RTL_8198),y)
TARGET = 98
else
TARGET = 96C
endif

ifeq ($(CONFIG_MODEL_RTL8198_MP),y)
TARGET = 98_MP
endif

ifeq ($(CONFIG_MODEL_RTL8196C_MP),y)
TARGET = 96C_MP
endif

ifeq ($(CONFIG_RTL_IPTABLES_FAST_PATH),m)
EXTRA_CFLAGS += -DCONFIG_RTK_IPTABLES_FAST_PATH
EXTRA_CFLAGS += -DCONFIG_FAST_PATH_MODULE

FASTPATH_OBJ=$(TARGET)/fastpath_core.o $(TARGET)/filter.o $(TARGET)/fast_pptp_core.o $(TARGET)/fast_l2tp_core.o
FASTPATH_MODULE=$(TARGET)/fastpath.o
obj-$(CONFIG_RTL_IPTABLES_FAST_PATH) += $(FASTPATH_MODULE)
fastpath-objs := $(FASTPATH_OBJ)

else
obj-$(CONFIG_RTL_IPTABLES_FAST_PATH) += $(TARGET)/fastpath_core.o $(TARGET)/filter_v2.o $(TARGET)/filter.o $(TARGET)/fast_pptp_core.o $(TARGET)/fast_l2tp_core.o
endif

obj-$(CONFIG_RTL_FAST_BRIDGE) += $(TARGET)/fast_br.o 

clean:
	rm -rf $(TARGET)/*.o $(TARGET)/*.ko $(TARGET)/*.mod.c

EXTRA_AFLAGS += $(EXTRA_CFLAGS)
