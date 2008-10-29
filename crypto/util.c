#include "isrcrypto.h"
#define LIBISRCRYPTO_INTERNAL
#include "internal.h"

exported const char *isrcry_strerror(enum isrcry_result result)
{
	switch (result) {
	case ISRCRY_OK:
		return "Success";
	case ISRCRY_INVALID_ARGUMENT:
		return "Invalid argument";
	}
	return "Unknown error";
}
