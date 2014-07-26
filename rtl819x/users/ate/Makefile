#
# ATE Makefile
#

DIR_USERS = $(DIR_ROOT)/users
INSTALLDIR = $(DIR_ROOT)/romfs
ROMFSINST = $(DIR_ROOT)/config/romfsinst
SHDIR = $(DIR_ROOT)/users/shared

CFLAGS  += -I. -I$(DIR_ROOT)/linux-2.6.30/include -I$(SHDIR)/include -I../httpd/LINUX -I../httpd/LINUX/system -I$(SHDIR) -I../nfbi/rtl_device -Wall
#-I$(DIR_ROOT)/linux-2.6.30/include/linux -I../../linux-2.6.30/drivers/char/rtl_mdio/
CFLAGS	+= -DWIFI_SIMPLE_CONFIG -DMODEL_NAME=\"$(MODEL_NAME)\"
 
LDFLAGS	= -L$(SHDIR) -L../httpd/LINUX -lapmib -lshared

all: ate

clean:
	rm -f *.o *~ ate

install: all

	install -d $(INSTALLDIR)/bin
	$(STRIP) ate
	install ate $(INSTALLDIR)/bin

romfs:
	$(ROMFSINST) ate /bin/ate
	cd $(INSTALLDIR)/bin && ln -sf ate ATE_Set_StartATEMode
	cd $(INSTALLDIR)/bin && ln -sf ate ATE_Set_AllLedOn
	cd $(INSTALLDIR)/bin && ln -sf ate ATE_Set_AllLedOff
	cd $(INSTALLDIR)/bin && ln -sf ate ATE_Set_MacAddr_2G
	cd $(INSTALLDIR)/bin && ln -sf ate ATE_Set_RegulationDomain
	cd $(INSTALLDIR)/bin && ln -sf ate ATE_Set_PINCode
	cd $(INSTALLDIR)/bin && ln -sf ate ATE_Set_RestoreDefault
	cd $(INSTALLDIR)/bin && ln -sf ate ATE_Get_FWVersion
	cd $(INSTALLDIR)/bin && ln -sf ate ATE_Get_BootLoaderVersion
	cd $(INSTALLDIR)/bin && ln -sf ate ATE_Get_ResetButtonStatus
	cd $(INSTALLDIR)/bin && ln -sf ate ATE_Get_WpsButtonStatus
	cd $(INSTALLDIR)/bin && ln -sf ate ATE_Get_MacAddr_2G
	cd $(INSTALLDIR)/bin && ln -sf ate ATE_Get_RegulationDomain
	cd $(INSTALLDIR)/bin && ln -sf ate ATE_Get_PINCode
	cd $(INSTALLDIR)/bin && ln -sf ate ATE_Get_WanLanStatus
	cd $(INSTALLDIR)/bin && ln -sf ate ATE_Get_FwReadyStatus
	cd $(INSTALLDIR)/bin && ln -sf ate ATE_Get_SWMode

ate: ate.o
	$(CC) -o $@ $^ $(LDFLAGS)
	$(STRIP) $@


