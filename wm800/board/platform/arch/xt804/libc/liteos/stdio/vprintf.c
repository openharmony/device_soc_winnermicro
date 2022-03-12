#include <stdio.h>

int vprintf(const char *restrict fmt, va_list ap)
{
	return wm_vprintf(fmt, ap);
}
