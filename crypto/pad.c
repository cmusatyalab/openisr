#include <unistd.h>
#include "isrcrypto.h"
#define LIBISRCRYPTO_INTERNAL
#include "internal.h"

enum isrcry_result _isrcry_pkcs5_pad(unsigned char *buf, unsigned blocklen,
			unsigned datalen)
{
	unsigned char pad;
	unsigned n;

	if (buf == NULL || datalen >= blocklen || blocklen - datalen > 255)
		return ISRCRY_INVALID_ARGUMENT;
	pad = blocklen - datalen;
	for (n = datalen; n < blocklen; n++)
		buf[n] = pad;
	return ISRCRY_OK;
}

enum isrcry_result _isrcry_pkcs5_unpad(unsigned char *buf, unsigned blocklen,
			unsigned *datalen)
{
	unsigned char pad;
	unsigned n;

	if (buf == NULL || datalen == NULL)
		return ISRCRY_INVALID_ARGUMENT;
	pad = buf[blocklen - 1];
	if (pad == 0 || pad > blocklen)
		return ISRCRY_BAD_PADDING;
	for (n = 1; n < pad; n++)
		if (buf[blocklen - n - 1] != pad)
			return ISRCRY_BAD_PADDING;
	*datalen = blocklen - pad;
	return ISRCRY_OK;
}
