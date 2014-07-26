#!/bin/sh

#Create folder for bootcode
mkdir ./bootcode_rtl8196c_98/boot/banner

#Untar toolchain.tar.gz
cd ./rtl819x && tar -zxvf toolchain.tar.gz && cd ..

#Create symbolic link file
ln -s boards/rtl8196c ./rtl819x/target
ln -s target/tmpfs ./rtl819x/tmpfs
ln -s target/romfs ./rtl819x/romfs
ln -s target/image ./rtl819x/image
ln -sf /home/hyking/jungle_1117/linux-2.6.30/drivers/net/rtl819x/AsicDriver/rtl865xc_asicregs.h ./rtl819x/linux-2.6.30/include/asm-mips/rtl865x/rtl865xc_asicregs.h
ln -sf /home/bo_zhao/8196/linux-2.6.19/linux-2.6.x/arch/mips/realtek/rtl8196b/pci-rtl8196.c ./rtl819x/linux-2.6.30/arch/mips/rtl8196b/pci.c
ln -sf ../../../target/bsp ./rtl819x/linux-2.6.30/arch/rlx/bsp
ln -sf etc.default ./rtl819x/boards/rtl8196c/etc
ln -sf busybox-1.13 ./rtl819x/users/busybox
