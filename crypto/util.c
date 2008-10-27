/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtomcrypt.com
 */

#include <string.h>
#include "isrcrypto.h"

/**
   Burn some stack memory
   @param len amount of stack to burn in bytes
*/
void burn_stack(unsigned long len)
{
	unsigned char buf[32];
	memset(buf, 0, sizeof(buf));
	if (len > (unsigned long)sizeof(buf))
		burn_stack(len - sizeof(buf));
}

const char *isrcry_strerror(enum isrcry_result result)
{
	switch (result) {
	case ISRCRY_OK:
		return "Success";
	case ISRCRY_INVALID_ARGUMENT:
		return "Invalid argument";
	}
	return "Unknown error";
}
