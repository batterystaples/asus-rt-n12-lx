/* $Id: vr4181.h,v 1.1.1.1 2011/01/19 10:11:11 jerry_jian Exp $
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1999 by Michael Klar
 */
#ifndef __ASM_MIPS_VR4181_H 
#define __ASM_MIPS_VR4181_H 

#include <asm/addrspace.h>

// CPU interrupts
#define VR41XX_IRQ_SW1       0  // IP0 - Software interrupt
#define VR41XX_IRQ_SW2       1  // IP1 - Software interrupt
#define VR41XX_IRQ_INT0      2  // IP2 - All but battery, high speed modem, and real time clock
#define VR41XX_IRQ_INT1      3  // IP3 - RTC Long1 (system timer)
#define VR41XX_IRQ_INT2      4  // IP4 - RTC Long2
#define VR41XX_IRQ_INT3      5  // IP5 - High Speed Modem (unused on VR4181)
#define VR41XX_IRQ_INT4      6  // IP6 - Unused
#define VR41XX_IRQ_TIMER     7  // IP7 - Timer interrupt from CPO_COMPARE (Note: RTC Long1 is the system timer.)

// Cascaded from VR41XX_IRQ_INT0 (ICU mapped interrupts)
#define VR41XX_IRQ_BATTERY   8
#define VR41XX_IRQ_POWER     9
#define VR41XX_IRQ_RTCL1     10  // Use VR41XX_IRQ_INT1 instead.
#define VR41XX_IRQ_ETIMER    11
#define VR41XX_IRQ_RFU12     12
#define VR41XX_IRQ_PIU       13
#define VR41XX_IRQ_AIU       14
#define VR41XX_IRQ_KIU       15
#define VR41XX_IRQ_GIU       16  // This is a cascade to IRQs 40-71. Do not use.
#define VR41XX_IRQ_SIU       17
#define VR41XX_IRQ_RFU18     18
#define VR41XX_IRQ_SOFT      19
#define VR41XX_IRQ_RFU20     20
#define VR41XX_IRQ_DOZEPIU   21
#define VR41XX_IRQ_RFU22     22
#define VR41XX_IRQ_RFU23     23
#define VR41XX_IRQ_RTCL2     24  // Use VR41XX_IRQ_INT2 instead.
#define VR41XX_IRQ_LED       25
#define VR41XX_IRQ_ECU       26  // (CompactFlash)
#define VR41XX_IRQ_CSU       27
#define VR41XX_IRQ_USB       28
#define VR41XX_IRQ_DMA       29
#define VR41XX_IRQ_LCD       30
#define VR41XX_IRQ_RFU31     31
#define VR41XX_IRQ_RFU32     32
#define VR41XX_IRQ_RFU33     33
#define VR41XX_IRQ_RFU34     34
#define VR41XX_IRQ_RFU35     35
#define VR41XX_IRQ_RFU36     36
#define VR41XX_IRQ_RFU37     37
#define VR41XX_IRQ_RFU38     38
#define VR41XX_IRQ_RFU39     39
// Note: Still need to do the extra VR4181 IRQ definitions

// Cascaded from VR41XX_IRQ_GIU
#define VR41XX_IRQ_GPIO0     40
#define VR41XX_IRQ_GPIO1     41
#define VR41XX_IRQ_GPIO2     42
#define VR41XX_IRQ_GPIO3     43
#define VR41XX_IRQ_GPIO4     44
#define VR41XX_IRQ_GPIO5     45
#define VR41XX_IRQ_GPIO6     46
#define VR41XX_IRQ_GPIO7     47
#define VR41XX_IRQ_GPIO8     48
#define VR41XX_IRQ_GPIO9     49
#define VR41XX_IRQ_GPIO10    50
#define VR41XX_IRQ_GPIO11    51
#define VR41XX_IRQ_GPIO12    52
#define VR41XX_IRQ_GPIO13    53
#define VR41XX_IRQ_GPIO14    54
#define VR41XX_IRQ_GPIO15    55

// Alternative to above GPIO IRQ defines
#define VR41XX_IRQ_GPIO(pin) ((VR41XX_IRQ_GPIO0) + (pin))

#define VR41XX_IRQ_MAX       55

#ifndef _LANGUAGE_ASSEMBLY
#define __preg8		(volatile unsigned char*)
#define __preg16	(volatile unsigned short*)
#define __preg32	(volatile unsigned int*)
#else
#define __preg8
#define __preg16
#define __preg32
#endif

// Embedded CPU peripheral registers
// Note that many of the registers have different physical address for VR4181

// Bus Control Unit (BCU)
#define VR41XX_BCUCNTREG1	__preg16(KSEG1 + 0x0A000000)	/* BCU control register 1 (R/W) */
#define VR41XX_CMUCLKMSK	__preg16(KSEG1 + 0x0A000004)	/* Clock mask register (R/W) */
#define VR41XX_CMUCLKMSK_MSKCSUPCLK  0x0040
#define VR41XX_CMUCLKMSK_MSKAIUPCLK  0x0020
#define VR41XX_CMUCLKMSK_MSKPIUPCLK  0x0010
#define VR41XX_CMUCLKMSK_MSKADUPCLK  0x0008
#define VR41XX_CMUCLKMSK_MSKSIU18M   0x0004
#define VR41XX_CMUCLKMSK_MSKADU18M   0x0002
#define VR41XX_CMUCLKMSK_MSKUSB      0x0001
#define VR41XX_CMUCLKMSK_MSKSIU      VR41XX_CMUCLKMSK_MSKSIU18M
#define VR41XX_BCUSPEEDREG	__preg16(KSEG1 + 0x0A00000C)	/* BCU access time parameter (R/W) */
#define VR41XX_BCURFCNTREG	__preg16(KSEG1 + 0x0A000010)	/* BCU refresh control register (R/W) */
#define VR41XX_REVIDREG		__preg16(KSEG1 + 0x0A000014)	/* Revision ID register (R) */
#define VR41XX_CLKSPEEDREG	__preg16(KSEG1 + 0x0A000018)	/* Clock speed register (R) */
#define VR41XX_EDOMCYTREG	__preg16(KSEG1 + 0x0A000300)	/* Memory cycle timing register (R/W) */
#define VR41XX_MEMCFG_REG	__preg16(KSEG1 + 0x0A000304)	/* Memory configuration register (R/W) */
#define VR41XX_MODE_REG		__preg16(KSEG1 + 0x0A000308)	/* SDRAM mode register (R/W) */
#define VR41XX_SDTIMINGREG	__preg16(KSEG1 + 0x0A00030C)	/* SDRAM timing register (R/W) */

// DMA Control Unit (DCU)
#define VR41XX_MICDEST1REG1	__preg16(KSEG1 + 0x0A000020)	/* Microphone destination 1 address register 1 (R/W) */
#define VR41XX_MICDEST1REG2	__preg16(KSEG1 + 0x0A000022)	/* Microphone destination 1 address register 2 (R/W) */
#define VR41XX_MICDEST2REG1	__preg16(KSEG1 + 0x0A000024)	/* Microphone destination 2 address register 1 (R/W) */
#define VR41XX_MICDEST2REG2	__preg16(KSEG1 + 0x0A000026)	/* Microphone destination 2 address register 2 (R/W) */
#define VR41XX_SPKRRC1REG1	__preg16(KSEG1 + 0x0A000028)	/* Speaker Source 1 address register 1 (R/W) */
#define VR41XX_SPKRRC1REG2	__preg16(KSEG1 + 0x0A00002A)	/* Speaker Source 1 address register 2 (R/W) */
#define VR41XX_SPKRRC2REG1	__preg16(KSEG1 + 0x0A00002C)	/* Speaker Source 2 address register 1 (R/W) */
#define VR41XX_SPKRRC2REG2	__preg16(KSEG1 + 0x0A00002E)	/* Speaker Source 2 address register 2 (R/W) */
#define VR41XX_DMARSTREG	__preg16(KSEG1 + 0x0A000040)	/* DMA Reset register (R/W) */
#define VR41XX_AIUDMAMSKREG	__preg16(KSEG1 + 0x0A000046)	/* Audio DMA mask register (R/W) */
#define VR41XX_USBDMAMSKREG	__preg16(KSEG1 + 0x0A000600)	/* USB DMA Mask register (R/W) */
#define VR41XX_USBRXS1AREG1	__preg16(KSEG1 + 0x0A000602)	/* USB Rx source 1 address register 1 (R/W) */
#define VR41XX_USBRXS1AREG2	__preg16(KSEG1 + 0x0A000604)	/* USB Rx source 1 address register 2 (R/W) */
#define VR41XX_USBRXS2AREG1	__preg16(KSEG1 + 0x0A000606)	/* USB Rx source 2 address register 1 (R/W) */
#define VR41XX_USBRXS2AREG2	__preg16(KSEG1 + 0x0A000608)	/* USB Rx source 2 address register 2 (R/W) */
#define VR41XX_USBTXS1AREG1	__preg16(KSEG1 + 0x0A00060A)	/* USB Tx source 1 address register 1 (R/W) */
#define VR41XX_USBTXS1AREG2	__preg16(KSEG1 + 0x0A00060C)	/* USB Tx source 1 address register 2 (R/W) */
#define VR41XX_USBTXS2AREG1	__preg16(KSEG1 + 0x0A00060E)	/* USB Tx source 2 address register 1 (R/W) */
#define VR41XX_USBTXS2AREG2	__preg16(KSEG1 + 0x0A000610)	/* USB Tx source 2 address register 2 (R/W) */
#define VR41XX_USBRXD1AREG1	__preg16(KSEG1 + 0x0A00062A)	/* USB Rx destination 1 address register 1 (R/W) */
#define VR41XX_USBRXD1AREG2	__preg16(KSEG1 + 0x0A00062C)	/* USB Rx destination 1 address register 2 (R/W) */
#define VR41XX_USBRXD2AREG1	__preg16(KSEG1 + 0x0A00062E)	/* USB Rx destination 2 address register 1 (R/W) */
#define VR41XX_USBRXD2AREG2	__preg16(KSEG1 + 0x0A000630)	/* USB Rx destination 2 address register 2 (R/W) */
#define VR41XX_USBTXD1AREG1	__preg16(KSEG1 + 0x0A000632)	/* USB Tx destination 1 address register 1 (R/W) */
#define VR41XX_USBTXD1AREG2	__preg16(KSEG1 + 0x0A000634)	/* USB Tx destination 1 address register 2 (R/W) */
#define VR41XX_USBTXD2AREG1	__preg16(KSEG1 + 0x0A000636)	/* USB Tx destination 2 address register 1 (R/W) */
#define VR41XX_USBTXD2AREG2	__preg16(KSEG1 + 0x0A000638)	/* USB Tx destination 2 address register 2 (R/W) */
#define VR41XX_RxRCLENREG	__preg16(KSEG1 + 0x0A000652)	/* USB Rx record length register (R/W) */
#define VR41XX_TxRCLENREG	__preg16(KSEG1 + 0x0A000654)	/* USB Tx record length register (R/W) */
#define VR41XX_MICRCLENREG	__preg16(KSEG1 + 0x0A000658)	/* Microphone record length register (R/W) */
#define VR41XX_SPKRCLENREG	__preg16(KSEG1 + 0x0A00065A)	/* Speaker record length register (R/W) */
#define VR41XX_USBCFGREG	__preg16(KSEG1 + 0x0A00065C)	/* USB configuration register (R/W) */
#define VR41XX_MICDMACFGREG	__preg16(KSEG1 + 0x0A00065E)	/* Microphone DMA configuration register (R/W) */
#define VR41XX_SPKDMACFGREG	__preg16(KSEG1 + 0x0A000660)	/* Speaker DMA configuration register (R/W) */
#define VR41XX_DMAITRQREG	__preg16(KSEG1 + 0x0A000662)	/* DMA interrupt request register (R/W) */
#define VR41XX_DMACLTREG	__preg16(KSEG1 + 0x0A000664)	/* DMA control register (R/W) */
#define VR41XX_DMAITMKREG	__preg16(KSEG1 + 0x0A000666)	/* DMA interrupt mask register (R/W) */

// ISA Bridge
#define VR41XX_ISABRGCTL	__preg16(KSEG1 + 0x0B0002C0)	/* ISA Bridge Control Register (R/W) */
#define VR41XX_ISABRGSTS	__preg16(KSEG1 + 0x0B0002C2)	/* ISA Bridge Status Register (R/W) */
#define VR41XX_XISACTL		__preg16(KSEG1 + 0x0B0002C4)	/* External ISA Control Register (R/W) */

// Clocked Serial Interface (CSI)
#define VR41XX_CSIMODE		__preg16(KSEG1 + 0x0B000900)	/* CSI Mode Register (R/W) */
#define VR41XX_CSIRXDATA	__preg16(KSEG1 + 0x0B000902)	/* CSI Receive Data Register (R) */
#define VR41XX_CSITXDATA	__preg16(KSEG1 + 0x0B000904)	/* CSI Transmit Data Register (R/W) */
#define VR41XX_CSILSTAT		__preg16(KSEG1 + 0x0B000906)	/* CSI Line Status Register (R/W) */
#define VR41XX_CSIINTMSK	__preg16(KSEG1 + 0x0B000908)	/* CSI Interrupt Mask Register (R/W) */
#define VR41XX_CSIINTSTAT	__preg16(KSEG1 + 0x0B00090a)	/* CSI Interrupt Status Register (R/W) */
#define VR41XX_CSITXBLEN	__preg16(KSEG1 + 0x0B00090c)	/* CSI Transmit Burst Length Register (R/W) */
#define VR41XX_CSIRXBLEN	__preg16(KSEG1 + 0x0B00090e)	/* CSI Receive Burst Length Register (R/W) */

// Interrupt Control Unit (ICU)
#define VR41XX_SYSINT1REG	__preg16(KSEG1 + 0x0A000080)	/* Level 1 System interrupt register 1 (R) */
#define VR41XX_MSYSINT1REG	__preg16(KSEG1 + 0x0A00008C)	/* Level 1 mask system interrupt register 1 (R/W) */
#define VR41XX_NMIREG		__preg16(KSEG1 + 0x0A000098)	/* NMI register (R/W) */
#define VR41XX_SOFTINTREG	__preg16(KSEG1 + 0x0A00009A)	/* Software interrupt register (R/W) */
#define VR41XX_SYSINT2REG	__preg16(KSEG1 + 0x0A000200)	/* Level 1 System interrupt register 2 (R) */
#define VR41XX_MSYSINT2REG	__preg16(KSEG1 + 0x0A000206)	/* Level 1 mask system interrupt register 2 (R/W) */
#define VR41XX_PIUINTREGro	__preg16(KSEG1 + 0x0B000082)	/* Level 2 PIU interrupt register (R) */
#define VR41XX_AIUINTREG	__preg16(KSEG1 + 0x0B000084)	/* Level 2 AIU interrupt register (R) */
#define VR41XX_MPIUINTREG	__preg16(KSEG1 + 0x0B00008E)	/* Level 2 mask PIU interrupt register (R/W) */
#define VR41XX_MAIUINTREG	__preg16(KSEG1 + 0x0B000090)	/* Level 2 mask AIU interrupt register (R/W) */
#define VR41XX_MKIUINTREG	__preg16(KSEG1 + 0x0B000092)	/* Level 2 mask KIU interrupt register (R/W) */
#define VR41XX_KIUINTREG	__preg16(KSEG1 + 0x0B000198)	/* Level 2 KIU interrupt register (R) */

// Power Management Unit (PMU)
#define VR41XX_PMUINTREG	__preg16(KSEG1 + 0x0B0000A0)	/* PMU Status Register (R/W) */
#define VR41XX_PMUINT_POWERSW  0x1	/* Power switch */
#define VR41XX_PMUINT_BATT     0x2	/* Low batt during normal operation */
#define VR41XX_PMUINT_DEADMAN  0x4	/* Deadman's switch */
#define VR41XX_PMUINT_RESET    0x8	/* Reset switch */
#define VR41XX_PMUINT_RTCRESET 0x10	/* RTC Reset */
#define VR41XX_PMUINT_TIMEOUT  0x20	/* HAL Timer Reset */
#define VR41XX_PMUINT_BATTLOW  0x100	/* Battery low */
#define VR41XX_PMUINT_RTC      0x200	/* RTC Alarm */
#define VR41XX_PMUINT_DCD      0x400	/* DCD# */
#define VR41XX_PMUINT_GPIO0    0x1000	/* GPIO0 */
#define VR41XX_PMUINT_GPIO1    0x2000	/* GPIO1 */
#define VR41XX_PMUINT_GPIO2    0x4000	/* GPIO2 */
#define VR41XX_PMUINT_GPIO3    0x8000	/* GPIO3 */

#define VR41XX_PMUCNTREG	__preg16(KSEG1 + 0x0B0000A2)	/* PMU Control Register (R/W) */
#define VR41XX_PMUWAITREG	__preg16(KSEG1 + 0x0B0000A8)	/* PMU Wait Counter Register (R/W) */
#define VR41XX_PMUDIVREG	__preg16(KSEG1 + 0x0B0000AC)	/* PMU Divide Mode Register (R/W) */
#define VR41XX_DRAMHIBCTL	__preg16(KSEG1 + 0x0B0000B2)	/* DRAM Hibernate Control Register (R/W) */

// Real Time Clock Unit (RTC)
#define VR41XX_ETIMELREG	__preg16(KSEG1 + 0x0B0000C0)	/* Elapsed Time L Register (R/W) */
#define VR41XX_ETIMEMREG	__preg16(KSEG1 + 0x0B0000C2)	/* Elapsed Time M Register (R/W) */
#define VR41XX_ETIMEHREG	__preg16(KSEG1 + 0x0B0000C4)	/* Elapsed Time H Register (R/W) */
#define VR41XX_ECMPLREG		__preg16(KSEG1 + 0x0B0000C8)	/* Elapsed Compare L Register (R/W) */
#define VR41XX_ECMPMREG		__preg16(KSEG1 + 0x0B0000CA)	/* Elapsed Compare M Register (R/W) */
#define VR41XX_ECMPHREG		__preg16(KSEG1 + 0x0B0000CC)	/* Elapsed Compare H Register (R/W) */
#define VR41XX_RTCL1LREG	__preg16(KSEG1 + 0x0B0000D0)	/* RTC Long 1 L Register (R/W) */
#define VR41XX_RTCL1HREG	__preg16(KSEG1 + 0x0B0000D2)	/* RTC Long 1 H Register (R/W) */
#define VR41XX_RTCL1CNTLREG	__preg16(KSEG1 + 0x0B0000D4)	/* RTC Long 1 Count L Register (R) */
#define VR41XX_RTCL1CNTHREG	__preg16(KSEG1 + 0x0B0000D6)	/* RTC Long 1 Count H Register (R) */
#define VR41XX_RTCL2LREG	__preg16(KSEG1 + 0x0B0000D8)	/* RTC Long 2 L Register (R/W) */
#define VR41XX_RTCL2HREG	__preg16(KSEG1 + 0x0B0000DA)	/* RTC Long 2 H Register (R/W) */
#define VR41XX_RTCL2CNTLREG	__preg16(KSEG1 + 0x0B0000DC)	/* RTC Long 2 Count L Register (R) */
#define VR41XX_RTCL2CNTHREG	__preg16(KSEG1 + 0x0B0000DE)	/* RTC Long 2 Count H Register (R) */
#define VR41XX_RTCINTREG	__preg16(KSEG1 + 0x0B0001DE)	/* RTC Interrupt Register (R/W) */

// Deadman's Switch Unit (DSU)
#define VR41XX_DSUCNTREG	__preg16(KSEG1 + 0x0B0000E0)	/* DSU Control Register (R/W) */
#define VR41XX_DSUSETREG	__preg16(KSEG1 + 0x0B0000E2)	/* DSU Dead Time Set Register (R/W) */
#define VR41XX_DSUCLRREG	__preg16(KSEG1 + 0x0B0000E4)	/* DSU Clear Register (W) */
#define VR41XX_DSUTIMREG	__preg16(KSEG1 + 0x0B0000E6)	/* DSU Elapsed Time Register (R/W) */

// General Purpose I/O Unit (GIU)
#define VR41XX_GPMD0REG		__preg16(KSEG1 + 0x0B000300)	/* GPIO Mode 0 Register (R/W) */
#define VR41XX_GPMD1REG		__preg16(KSEG1 + 0x0B000302)	/* GPIO Mode 1 Register (R/W) */
#define VR41XX_GPMD2REG		__preg16(KSEG1 + 0x0B000304)	/* GPIO Mode 2 Register (R/W) */
#define VR41XX_GPMD3REG		__preg16(KSEG1 + 0x0B000306)	/* GPIO Mode 3 Register (R/W) */
#define VR41XX_GPDATHREG	__preg16(KSEG1 + 0x0B000308)	/* GPIO Data High Register (R/W) */
#define VR41XX_GPDATHREG_GPIO16  0x0001
#define VR41XX_GPDATHREG_GPIO17  0x0002
#define VR41XX_GPDATHREG_GPIO18  0x0004
#define VR41XX_GPDATHREG_GPIO19  0x0008
#define VR41XX_GPDATHREG_GPIO20  0x0010
#define VR41XX_GPDATHREG_GPIO21  0x0020
#define VR41XX_GPDATHREG_GPIO22  0x0040
#define VR41XX_GPDATHREG_GPIO23  0x0080
#define VR41XX_GPDATHREG_GPIO24  0x0100
#define VR41XX_GPDATHREG_GPIO25  0x0200
#define VR41XX_GPDATHREG_GPIO26  0x0400
#define VR41XX_GPDATHREG_GPIO27  0x0800
#define VR41XX_GPDATHREG_GPIO28  0x1000
#define VR41XX_GPDATHREG_GPIO29  0x2000
#define VR41XX_GPDATHREG_GPIO30  0x4000
#define VR41XX_GPDATHREG_GPIO31  0x8000
#define VR41XX_GPDATLREG	__preg16(KSEG1 + 0x0B00030A)	/* GPIO Data Low Register (R/W) */
#define VR41XX_GPDATLREG_GPIO0   0x0001
#define VR41XX_GPDATLREG_GPIO1   0x0002
#define VR41XX_GPDATLREG_GPIO2   0x0004
#define VR41XX_GPDATLREG_GPIO3   0x0008
#define VR41XX_GPDATLREG_GPIO4   0x0010
#define VR41XX_GPDATLREG_GPIO5   0x0020
#define VR41XX_GPDATLREG_GPIO6   0x0040
#define VR41XX_GPDATLREG_GPIO7   0x0080
#define VR41XX_GPDATLREG_GPIO8   0x0100
#define VR41XX_GPDATLREG_GPIO9   0x0200
#define VR41XX_GPDATLREG_GPIO10  0x0400
#define VR41XX_GPDATLREG_GPIO11  0x0800
#define VR41XX_GPDATLREG_GPIO12  0x1000
#define VR41XX_GPDATLREG_GPIO13  0x2000
#define VR41XX_GPDATLREG_GPIO14  0x4000
#define VR41XX_GPDATLREG_GPIO15  0x8000
#define VR41XX_GPINTEN		__preg16(KSEG1 + 0x0B00030C)	/* GPIO Interrupt Enable Register (R/W) */
#define VR41XX_GPINTMSK		__preg16(KSEG1 + 0x0B00030E)	/* GPIO Interrupt Mask Register (R/W) */
#define VR41XX_GPINTTYPH	__preg16(KSEG1 + 0x0B000310)	/* GPIO Interrupt Type High Register (R/W) */
#define VR41XX_GPINTTYPL	__preg16(KSEG1 + 0x0B000312)	/* GPIO Interrupt Type Low Register (R/W) */
#define VR41XX_GPINTSTAT	__preg16(KSEG1 + 0x0B000314)	/* GPIO Interrupt Status Register (R/W) */
#define VR41XX_GPHIBSTH		__preg16(KSEG1 + 0x0B000316)	/* GPIO Hibernate Pin State High Register (R/W) */
#define VR41XX_GPHIBSTL		__preg16(KSEG1 + 0x0B000318)	/* GPIO Hibernate Pin State Low Register (R/W) */
#define VR41XX_GPSICTL		__preg16(KSEG1 + 0x0B00031A)	/* GPIO Serial Interface Control Register (R/W) */
#define VR41XX_KEYEN		__preg16(KSEG1 + 0x0B00031C)	/* Keyboard Scan Pin Enable Register (R/W) */
#define VR41XX_PCS0STRA		__preg16(KSEG1 + 0x0B000320)	/* Programmable Chip Select [0] Start Address Register (R/W) */
#define VR41XX_PCS0STPA		__preg16(KSEG1 + 0x0B000322)	/* Programmable Chip Select [0] Stop Address Register (R/W) */
#define VR41XX_PCS0HIA		__preg16(KSEG1 + 0x0B000324)	/* Programmable Chip Select [0] High Address Register (R/W) */
#define VR41XX_PCS1STRA		__preg16(KSEG1 + 0x0B000326)	/* Programmable Chip Select [1] Start Address Register (R/W) */
#define VR41XX_PCS1STPA		__preg16(KSEG1 + 0x0B000328)	/* Programmable Chip Select [1] Stop Address Register (R/W) */
#define VR41XX_PCS1HIA		__preg16(KSEG1 + 0x0B00032A)	/* Programmable Chip Select [1] High Address Register (R/W) */
#define VR41XX_PCSMODE		__preg16(KSEG1 + 0x0B00032C)	/* Programmable Chip Select Mode Register (R/W) */
#define VR41XX_LCDGPMODE	__preg16(KSEG1 + 0x0B00032E)	/* LCD General Purpose Mode Register (R/W) */
#define VR41XX_MISCREG0		__preg16(KSEG1 + 0x0B000330)	/* Misc. R/W Battery Backed Registers for Non-Volatile Storage (R/W) */
#define VR41XX_MISCREG1		__preg16(KSEG1 + 0x0B000332)	/* Misc. R/W Battery Backed Registers for Non-Volatile Storage (R/W) */
#define VR41XX_MISCREG2		__preg16(KSEG1 + 0x0B000334)	/* Misc. R/W Battery Backed Registers for Non-Volatile Storage (R/W) */
#define VR41XX_MISCREG3		__preg16(KSEG1 + 0x0B000336)	/* Misc. R/W Battery Backed Registers for Non-Volatile Storage (R/W) */
#define VR41XX_MISCREG4		__preg16(KSEG1 + 0x0B000338)	/* Misc. R/W Battery Backed Registers for Non-Volatile Storage (R/W) */
#define VR41XX_MISCREG5		__preg16(KSEG1 + 0x0B00033A)	/* Misc. R/W Battery Backed Registers for Non-Volatile Storage (R/W) */
#define VR41XX_MISCREG6		__preg16(KSEG1 + 0x0B00033C)	/* Misc. R/W Battery Backed Registers for Non-Volatile Storage (R/W) */
#define VR41XX_MISCREG7		__preg16(KSEG1 + 0x0B00033D)	/* Misc. R/W Battery Backed Registers for Non-Volatile Storage (R/W) */
#define VR41XX_MISCREG8		__preg16(KSEG1 + 0x0B000340)	/* Misc. R/W Battery Backed Registers for Non-Volatile Storage (R/W) */
#define VR41XX_MISCREG9		__preg16(KSEG1 + 0x0B000342)	/* Misc. R/W Battery Backed Registers for Non-Volatile Storage (R/W) */
#define VR41XX_MISCREG10	__preg16(KSEG1 + 0x0B000344)	/* Misc. R/W Battery Backed Registers for Non-Volatile Storage (R/W) */
#define VR41XX_MISCREG11	__preg16(KSEG1 + 0x0B000346)	/* Misc. R/W Battery Backed Registers for Non-Volatile Storage (R/W) */
#define VR41XX_MISCREG12	__preg16(KSEG1 + 0x0B000348)	/* Misc. R/W Battery Backed Registers for Non-Volatile Storage (R/W) */
#define VR41XX_MISCREG13	__preg16(KSEG1 + 0x0B00034A)	/* Misc. R/W Battery Backed Registers for Non-Volatile Storage (R/W) */
#define VR41XX_MISCREG14	__preg16(KSEG1 + 0x0B00034C)	/* Misc. R/W Battery Backed Registers for Non-Volatile Storage (R/W) */
#define VR41XX_MISCREG15	__preg16(KSEG1 + 0x0B00034E)	/* Misc. R/W Battery Backed Registers for Non-Volatile Storage (R/W) */
#define VR41XX_SECIRQMASKL	VR41XX_GPINTEN
// No SECIRQMASKH for VR4181

// Touch Panel Interface Unit (PIU)
#define VR41XX_PIUCNTREG	__preg16(KSEG1 + 0x0B000122)	/* PIU Control register (R/W) */
#define VR41XX_PIUCNTREG_PIUSEQEN	0x0004
#define VR41XX_PIUCNTREG_PIUPWR		0x0002
#define VR41XX_PIUCNTREG_PADRST		0x0001

#define VR41XX_PIUINTREG	__preg16(KSEG1 + 0x0B000124)	/* PIU Interrupt cause register (R/W) */
#define VR41XX_PIUINTREG_OVP		0x8000
#define VR41XX_PIUINTREG_PADCMD		0x0040
#define VR41XX_PIUINTREG_PADADP		0x0020
#define VR41XX_PIUINTREG_PADPAGE1	0x0010
#define VR41XX_PIUINTREG_PADPAGE0	0x0008
#define VR41XX_PIUINTREG_PADDLOST	0x0004
#define VR41XX_PIUINTREG_PENCHG		0x0001

#define VR41XX_PIUSIVLREG	__preg16(KSEG1 + 0x0B000126)	/* PIU Data sampling interval register (R/W) */
#define VR41XX_PIUSTBLREG	__preg16(KSEG1 + 0x0B000128)	/* PIU A/D converter start delay register (R/W) */
#define VR41XX_PIUCMDREG	__preg16(KSEG1 + 0x0B00012A)	/* PIU A/D command register (R/W) */
#define VR41XX_PIUASCNREG	__preg16(KSEG1 + 0x0B000130)	/* PIU A/D port scan register (R/W) */
#define VR41XX_PIUAMSKREG	__preg16(KSEG1 + 0x0B000132)	/* PIU A/D scan mask register (R/W) */
#define VR41XX_PIUCIVLREG	__preg16(KSEG1 + 0x0B00013E)	/* PIU Check interval register (R) */
#define VR41XX_PIUPB00REG	__preg16(KSEG1 + 0x0B0002A0)	/* PIU Page 0 Buffer 0 register (R/W) */
#define VR41XX_PIUPB01REG	__preg16(KSEG1 + 0x0B0002A2)	/* PIU Page 0 Buffer 1 register (R/W) */
#define VR41XX_PIUPB02REG	__preg16(KSEG1 + 0x0B0002A4)	/* PIU Page 0 Buffer 2 register (R/W) */
#define VR41XX_PIUPB03REG	__preg16(KSEG1 + 0x0B0002A6)	/* PIU Page 0 Buffer 3 register (R/W) */
#define VR41XX_PIUPB10REG	__preg16(KSEG1 + 0x0B0002A8)	/* PIU Page 1 Buffer 0 register (R/W) */
#define VR41XX_PIUPB11REG	__preg16(KSEG1 + 0x0B0002AA)	/* PIU Page 1 Buffer 1 register (R/W) */
#define VR41XX_PIUPB12REG	__preg16(KSEG1 + 0x0B0002AC)	/* PIU Page 1 Buffer 2 register (R/W) */
#define VR41XX_PIUPB13REG	__preg16(KSEG1 + 0x0B0002AE)	/* PIU Page 1 Buffer 3 register (R/W) */
#define VR41XX_PIUAB0REG	__preg16(KSEG1 + 0x0B0002B0)	/* PIU A/D scan Buffer 0 register (R/W) */
#define VR41XX_PIUAB1REG	__preg16(KSEG1 + 0x0B0002B2)	/* PIU A/D scan Buffer 1 register (R/W) */
#define VR41XX_PIUAB2REG	__preg16(KSEG1 + 0x0B0002B4)	/* PIU A/D scan Buffer 2 register (R/W) */
#define VR41XX_PIUAB3REG	__preg16(KSEG1 + 0x0B0002B6)	/* PIU A/D scan Buffer 3 register (R/W) */
#define VR41XX_PIUPB04REG	__preg16(KSEG1 + 0x0B0002BC)	/* PIU Page 0 Buffer 4 register (R/W) */
#define VR41XX_PIUPB14REG	__preg16(KSEG1 + 0x0B0002BE)	/* PIU Page 1 Buffer 4 register (R/W) */

// Audio Interface Unit (AIU)
#define VR41XX_SODATREG		__preg16(KSEG1 + 0x0B000166)	/* Speaker Output Data Register (R/W) */
#define VR41XX_SCNTREG		__preg16(KSEG1 + 0x0B000168)	/* Speaker Output Control Register (R/W) */
#define VR41XX_MIDATREG		__preg16(KSEG1 + 0x0B000170)	/* Mike Input Data Register (R/W) */
#define VR41XX_MCNTREG		__preg16(KSEG1 + 0x0B000172)	/* Mike Input Control Register (R/W) */
#define VR41XX_DVALIDREG	__preg16(KSEG1 + 0x0B000178)	/* Data Valid Register (R/W) */
#define VR41XX_SEQREG		__preg16(KSEG1 + 0x0B00017A)	/* Sequential Register (R/W) */
#define VR41XX_INTREG		__preg16(KSEG1 + 0x0B00017C)	/* Interrupt Register (R/W) */
#define VR41XX_SDMADATREG	__preg16(KSEG1 + 0x0B000160)	/* Speaker DMA Data Register (R/W) */
#define VR41XX_MDMADATREG	__preg16(KSEG1 + 0x0B000162)	/* Microphone DMA Data Register (R/W) */
#define VR41XX_DAVREF_SETUP	__preg16(KSEG1 + 0x0B000164)	/* DAC Vref setup register (R/W) */
#define VR41XX_SCNVC_END	__preg16(KSEG1 + 0x0B00016E)	/* Speaker sample rate control (R/W) */
#define VR41XX_MIDATREG		__preg16(KSEG1 + 0x0B000170)	/* Microphone Input Data Register (R/W) */
#define VR41XX_MCNTREG		__preg16(KSEG1 + 0x0B000172)	/* Microphone Input Control Register (R/W) */
#define VR41XX_MCNVC_END	__preg16(KSEG1 + 0x0B00017E)	/* Microphone sample rate control (R/W) */

// Keyboard Interface Unit (KIU)
#define VR41XX_KIUDAT0		__preg16(KSEG1 + 0x0B000180)	/* KIU Data0 Register (R/W) */
#define VR41XX_KIUDAT1		__preg16(KSEG1 + 0x0B000182)	/* KIU Data1 Register (R/W) */
#define VR41XX_KIUDAT2		__preg16(KSEG1 + 0x0B000184)	/* KIU Data2 Register (R/W) */
#define VR41XX_KIUDAT3		__preg16(KSEG1 + 0x0B000186)	/* KIU Data3 Register (R/W) */
#define VR41XX_KIUDAT4		__preg16(KSEG1 + 0x0B000188)	/* KIU Data4 Register (R/W) */
#define VR41XX_KIUDAT5		__preg16(KSEG1 + 0x0B00018A)	/* KIU Data5 Register (R/W) */
#define VR41XX_KIUSCANREP	__preg16(KSEG1 + 0x0B000190)	/* KIU Scan/Repeat Register (R/W) */
#define VR41XX_KIUSCANREP_KEYEN      0x8000
#define VR41XX_KIUSCANREP_SCANSTP    0x0008
#define VR41XX_KIUSCANREP_SCANSTART  0x0004
#define VR41XX_KIUSCANREP_ATSTP      0x0002
#define VR41XX_KIUSCANREP_ATSCAN     0x0001
#define VR41XX_KIUSCANS		__preg16(KSEG1 + 0x0B000192)	/* KIU Scan Status Register (R) */
#define VR41XX_KIUWKS		__preg16(KSEG1 + 0x0B000194)	/* KIU Wait Keyscan Stable Register (R/W) */
#define VR41XX_KIUWKI		__preg16(KSEG1 + 0x0B000196)	/* KIU Wait Keyscan Interval Register (R/W) */
#define VR41XX_KIUINT		__preg16(KSEG1 + 0x0B000198)	/* KIU Interrupt Register (R/W) */
#define VR41XX_KIUINT_KDATLOST       0x0004
#define VR41XX_KIUINT_KDATRDY        0x0002
#define VR41XX_KIUINT_SCANINT        0x0001
#define VR41XX_KIUDAT6		__preg16(KSEG1 + 0x0B00018C)	/* Scan Line 6 Key Data Register (R) */
#define VR41XX_KIUDAT7		__preg16(KSEG1 + 0x0B00018E)	/* Scan Line 7 Key Data Register (R) */

// CompactFlash Controller
#define VR41XX_PCCARDINDEX	__preg8(KSEG1 + 0x0B0008E0)	/* PC Card Controller Index Register */
#define VR41XX_PCCARDDATA	__preg8(KSEG1 + 0x0B0008E1)	/* PC Card Controller Data Register */
#define VR41XX_INTSTATREG	__preg16(KSEG1 + 0x0B0008F8)	/* Interrupt Status Register (R/W) */
#define VR41XX_INTMSKREG	__preg16(KSEG1 + 0x0B0008FA)	/* Interrupt Mask Register (R/W) */
#define VR41XX_CFG_REG_1	__preg16(KSEG1 + 0x0B0008FE)	/* Configuration Register 1 */

// LED Control Unit (LED)
#define VR41XX_LEDHTSREG	__preg16(KSEG1 + 0x0B000240)	/* LED H Time Set register (R/W) */
#define VR41XX_LEDLTSREG	__preg16(KSEG1 + 0x0B000242)	/* LED L Time Set register (R/W) */
#define VR41XX_LEDCNTREG	__preg16(KSEG1 + 0x0B000248)	/* LED Control register (R/W) */
#define VR41XX_LEDASTCREG	__preg16(KSEG1 + 0x0B00024A)	/* LED Auto Stop Time Count register (R/W) */
#define VR41XX_LEDINTREG	__preg16(KSEG1 + 0x0B00024C)	/* LED Interrupt register (R/W) */

// Serial Interface Unit (SIU / SIU1 and SIU2)
#define VR41XX_SIURB		__preg8(KSEG1 + 0x0C000010)	/* Receiver Buffer Register (Read) DLAB = 0 (R) */
#define VR41XX_SIUTH		__preg8(KSEG1 + 0x0C000010)	/* Transmitter Holding Register (Write) DLAB = 0 (W) */
#define VR41XX_SIUDLL		__preg8(KSEG1 + 0x0C000010)	/* Divisor Latch (Least Significant Byte) DLAB = 1 (R/W) */
#define VR41XX_SIUIE		__preg8(KSEG1 + 0x0C000011)	/* Interrupt Enable DLAB = 0 (R/W) */
#define VR41XX_SIUDLM		__preg8(KSEG1 + 0x0C000011)	/* Divisor Latch (Most Significant Byte) DLAB = 1 (R/W) */
#define VR41XX_SIUIID		__preg8(KSEG1 + 0x0C000012)	/* Interrupt Identification Register (Read) (R) */
#define VR41XX_SIUFC		__preg8(KSEG1 + 0x0C000012)	/* FIFO Control Register (Write) (W) */
#define VR41XX_SIULC		__preg8(KSEG1 + 0x0C000013)	/* Line Control Register (R/W) */
#define VR41XX_SIUMC		__preg8(KSEG1 + 0x0C000014)	/* MODEM Control Register (R/W) */
#define VR41XX_SIULS		__preg8(KSEG1 + 0x0C000015)	/* Line Status Register (R/W) */
#define VR41XX_SIUMS		__preg8(KSEG1 + 0x0C000016)	/* MODEM Status Register (R/W) */
#define VR41XX_SIUSC		__preg8(KSEG1 + 0x0C000017)	/* Scratch Register (R/W) */
#define VR41XX_SIURESET		__preg8(KSEG1 + 0x0C000019)	/* SIU Reset Register (R/W) */
#define VR41XX_SIUACTMSK	__preg8(KSEG1 + 0x0C00001C)	/* SIU Activity Mask (R/W) */
#define VR41XX_SIUACTTMR	__preg8(KSEG1 + 0x0C00001E)	/* SIU Activity Timer (R/W) */
#define VR41XX_SIURB_2		__preg8(KSEG1 + 0x0C000000)	/* Receive Buffer Register (Read) (R) */
#define VR41XX_SIUTH_2		__preg8(KSEG1 + 0x0C000000)	/* Transmitter Holding Register (Write) (W) */
#define VR41XX_SIUDLL_2		__preg8(KSEG1 + 0x0C000000)	/* Divisor Latch (Least Significant Byte) (R/W) */
#define VR41XX_SIUIE_2		__preg8(KSEG1 + 0x0C000001)	/* Interrupt Enable (DLAB = 0) (R/W) */
#define VR41XX_SIUDLM_2		__preg8(KSEG1 + 0x0C000001)	/* Divisor Latch (Most Significant Byte) (DLAB = 1) (R/W) */
#define VR41XX_SIUIID_2		__preg8(KSEG1 + 0x0C000002)	/* Interrupt Identification Register (Read) (R) */
#define VR41XX_SIUFC_2		__preg8(KSEG1 + 0x0C000002)	/* FIFO Control Register (Write) (W) */
#define VR41XX_SIULC_2		__preg8(KSEG1 + 0x0C000003)	/* Line Control Register (R/W) */
#define VR41XX_SIUMC_2		__preg8(KSEG1 + 0x0C000004)	/* Modem Control Register (R/W) */
#define VR41XX_SIULS_2		__preg8(KSEG1 + 0x0C000005)	/* Line Status Register (R/W) */
#define VR41XX_SIUMS_2		__preg8(KSEG1 + 0x0C000006)	/* Modem Status Register (R/W) */
#define VR41XX_SIUSC_2		__preg8(KSEG1 + 0x0C000007)	/* Scratch Register (R/W) */
#define VR41XX_SIUIRSEL_2	__preg8(KSEG1 + 0x0C000008)	/* SIU IrDA Selectot (R/W) */
#define VR41XX_SIURESET_2	__preg8(KSEG1 + 0x0C000009)	/* SIU Reset Register (R/W) */
#define VR41XX_SIUCSEL_2	__preg8(KSEG1 + 0x0C00000A)	/* IrDA Echo-back Control (R/W) */
#define VR41XX_SIUACTMSK_2	__preg8(KSEG1 + 0x0C00000C)	/* SIU Activity Mask Register (R/W) */
#define VR41XX_SIUACTTMR_2	__preg8(KSEG1 + 0x0C00000E)	/* SIU Activity Timer Register (R/W) */


// USB Module
#define VR41XX_USBINFIFO	__preg16(KSEG1 + 0x0B000780)	/* USB Bulk Input FIFO (Bulk In End Point) (W) */
#define VR41XX_USBOUTFIFO	__preg16(KSEG1 + 0x0B000782)	/* USB Bulk Output FIFO (Bulk Out End Point) (R) */
#define VR41XX_USBCTLFIFO	__preg16(KSEG1 + 0x0B000784)	/* USB Control FIFO (Control End Point) (W) */
#define VR41XX_USBSTAT		__preg16(KSEG1 + 0x0B000786)	/* Interrupt Status Register (R/W) */
#define VR41XX_USBINTMSK	__preg16(KSEG1 + 0x0B000788)	/* Interrupt Mask Register (R/W) */
#define VR41XX_USBCTLREG	__preg16(KSEG1 + 0x0B00078A)	/* Control Register (R/W) */
#define VR41XX_USBSTPREG	__preg16(KSEG1 + 0x0B00078C)	/* USB Transfer Stop Register (R/W) */

// LCD Controller
#define VR41XX_HRTOTALREG	__preg16(KSEG1 + 0x0A000400)	/* Horizontal total Register (R/W) */
#define VR41XX_HRVISIBREG	__preg16(KSEG1 + 0x0A000402)	/* Horizontal Visible Register (R/W) */
#define VR41XX_LDCLKSTREG	__preg16(KSEG1 + 0x0A000404)	/* Load clock start Register (R/W) */
#define VR41XX_LDCLKNDREG	__preg16(KSEG1 + 0x0A000406)	/* Load clock end Register (R/W) */
#define VR41XX_VRTOTALREG	__preg16(KSEG1 + 0x0A000408)	/* Vertical Total Register (R/W) */
#define VR41XX_VRVISIBREG	__preg16(KSEG1 + 0x0A00040A)	/* Vertical Visible Register (R/W) */
#define VR41XX_FVSTARTREG	__preg16(KSEG1 + 0x0A00040C)	/* FLM vertical start Register (R/W) */
#define VR41XX_FVENDREG		__preg16(KSEG1 + 0x0A00040E)	/* FLM vertical end Register (R/W) */
#define VR41XX_LCDCTRLREG	__preg16(KSEG1 + 0x0A000410)	/* LCD control Register (R/W) */
#define VR41XX_LCDINRQREG	__preg16(KSEG1 + 0x0A000412)	/* LCD Interrupt request Register (R/W) */
#define VR41XX_LCDCFGREG0	__preg16(KSEG1 + 0x0A000414)	/* LCD Configuration Register 0 (R/W) */
#define VR41XX_LCDCFGREG1	__preg16(KSEG1 + 0x0A000416)	/* LCD Configuration Register 1 (R/W) */
#define VR41XX_FBSTAD1REG	__preg16(KSEG1 + 0x0A000418)	/* Frame Buffer Start Address 1 Register (R/W) */
#define VR41XX_FBSTAD2REG	__preg16(KSEG1 + 0x0A00041A)	/* Frame Buffer Start Address 2 Register (R/W) */
#define VR41XX_FBNDAD1REG	__preg16(KSEG1 + 0x0A000420)	/* Frame Buffer End Address 1 Register (R/W) */
#define VR41XX_FBNDAD2REG	__preg16(KSEG1 + 0x0A000422)	/* Frame Buffer End Address 2 register (R/W) */
#define VR41XX_FHSTARTREG	__preg16(KSEG1 + 0x0A000424)	/* FLM horizontal Start Register (R/W) */
#define VR41XX_FHENDREG		__preg16(KSEG1 + 0x0A000426)	/* FLM horizontal End Register (R/W) */
#define VR41XX_PWRCONREG1	__preg16(KSEG1 + 0x0A000430)	/* Power Control register 1 (R/W) */
#define VR41XX_PWRCONREG2	__preg16(KSEG1 + 0x0A000432)	/* Power Control register 2 (R/W) */
#define VR41XX_LCDIMSKREG	__preg16(KSEG1 + 0x0A000434)	/* LCD Interrupt Mask register (R/W) */
#define VR41XX_CPINDCTREG	__preg16(KSEG1 + 0x0A00047E)	/* Color palette Index and control Register (R/W) */
#define VR41XX_CPALDATREG	__preg32(KSEG1 + 0x0A000480)	/* Color palette data register (32bits Register) (R/W) */

// physical address spaces
#define VR41XX_LCD             0x0a000000
#define VR41XX_INTERNAL_IO_2   0x0b000000
#define VR41XX_INTERNAL_IO_1   0x0c000000
#define VR41XX_ISA_MEM         0x10000000
#define VR41XX_ISA_IO          0x14000000
#define VR41XX_ROM             0x18000000

// This is the base address for IO port decoding to which the 16 bit IO port address
// is added.  Defining it to 0 will usually cause a kernel oops any time port IO is
// attempted, which can be handy for turning up parts of the kernel that make
// incorrect architecture assumptions (by assuming that everything acts like a PC),
// but we need it correctly defined to use the PCMCIA/CF controller:
#define VR41XX_PORT_BASE	(KSEG1 + VR41XX_ISA_IO)
#define VR41XX_ISAMEM_BASE	(KSEG1 + VR41XX_ISA_MEM)

#endif /* __ASM_MIPS_VR4181_H */
