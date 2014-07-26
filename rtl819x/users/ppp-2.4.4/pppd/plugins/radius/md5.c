/*
 * $Id: md5.c,v 1.1.1.1 2011/01/19 10:19:06 jerry_jian Exp $
 */
#include "md5.h"

void rc_md5_calc (unsigned char *output, unsigned char *input, unsigned int inlen)
{
	MD5_CTX         context;

	MD5_Init (&context);
	MD5_Update (&context, input, inlen);
	MD5_Final (output, &context);
}
