#include "stdio_impl.h"

int puts(const char *s)
{
	return wm_printf(s);
}
