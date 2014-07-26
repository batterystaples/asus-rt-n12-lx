/*
 *      File to define f/w version number
 *
 *      Authors: David Hsu	<davidhsu@realtek.com.tw>
 *
 *      $Id: version.c,v 1.2 2011/05/16 01:58:10 jerry_jian Exp $
 *
 */
#ifdef CONFIG_RTL_8196B
#ifdef CONFIG_RTL8196B_TLD
 unsigned char *fwVersion="v1.4_TD";
#else
 unsigned char *fwVersion="v1.4";
#endif
#elif defined(CONFIG_RTL_8196C) || defined(CONFIG_RTL_8198)
unsigned char *fwVersion="v2.4";
#else
 unsigned char *fwVersion="v1.2f";
#endif
#define SDK_VERSION "2.4"
