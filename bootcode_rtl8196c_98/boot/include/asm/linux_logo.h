/* $Id: linux_logo.h,v 1.1.1.1 2011/01/19 10:11:11 jerry_jian Exp $
 *
 * include/asm-mips/linux_logo.h: This is a linux logo
 *                                to be displayed on boot.
 *
 * Copyright (C) 1996 Larry Ewing (lewing@isc.tamu.edu)
 * Copyright (C) 1998 Jakub Jelinek (jj@sunsite.mff.cuni.cz)
 *
 * You can put anything here, but:
 * LINUX_LOGO_COLORS has to be less than 224
 * image size has to be 80x80
 * values have to start from 0x20
 * (i.e. RGB(linux_logo_red[0],
 *	     linux_logo_green[0],
 *	     linux_logo_blue[0]) is color 0x20)
 * BW image has to be 80x80 as well, with MS bit
 * on the left
 * Serial_console ascii image can be any size,
 * but should contain %s to display the version
 */
 
#include <linux/init.h>
#include <linux/version.h>
#include <linux/config.h>

#ifdef CONFIG_CPU_VR41XX
  #include <linux/init.h>
  #include <linux/version.h>

  #define linux_logo_banner "Linux VR version " UTS_RELEASE

  #define LINUX_LOGO_COLORS 214
  #define INCLUDE_LINUX_LOGO16
  #define INCLUDE_LINUX_LOGOBW

  #ifdef INCLUDE_LINUX_LOGO_DATA
    #include "linux_logo_vr.h"
  #endif
#else
  #include "linux_logo_sgi.h"
#endif
