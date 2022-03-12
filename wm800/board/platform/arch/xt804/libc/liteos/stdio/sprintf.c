#include <stdio.h>
#include <stdarg.h>

int sprintf(char *restrict s, const char *restrict fmt, ...)
{
#if 0
	int ret;
	va_list ap;
	va_start(ap, fmt);
	ret = vsprintf(s, fmt, ap);
	va_end(ap);
	return ret;
#else
	va_list ap;
    int i;

	va_start(ap, fmt);
	i = wm_vsnprintf(s, (size_t) - 1, fmt, ap);
	va_end(ap);

	return i;
#endif
}
