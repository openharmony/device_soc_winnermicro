/*
 * Copyright (C) 2017 C-SKY Microsystems Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/******************************************************************************
 * @file     libc_port.c
 * @brief    libc port
 * @version  V1.0
 * @date     26. Dec 2017
 ******************************************************************************/

#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <limits.h>
#include <csi_config.h>
#include "stddef.h"
#include "wm_config.h"
#include "wm_regs.h"
/* Minimum and maximum values a `signed int' can hold.  */
#   ifndef __INT_MAX__
#    define __INT_MAX__ 2147483647
#   endif
#   undef INT_MIN
#   define INT_MIN (-INT_MAX-1)
#   undef INT_MAX
#   define INT_MAX __INT_MAX__

/* Maximum value an `unsigned int' can hold.  (Minimum is 0).  */
#   undef UINT_MAX
#   define UINT_MAX (INT_MAX * 2U + 1)

#   undef SIZE_MAX
#   define SIZE_MAX (INT_MAX * 2U + 1)
#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

static unsigned char printf_port = 0;
unsigned char get_printf_port(void)
{
    return printf_port;
}

void set_printf_port(unsigned char port)
{
    if (port == 0) {
        printf_port = 0;
    } else if (port == 1) {
        printf_port = 1;
    } else {
        printf_port = 0xff;
    }
}

int sendchar(int ch)
{
    if (printf_port == 0) {
        if (ch == '\n') {
            while (tls_reg_read32(HR_UART0_FIFO_STATUS) & 0x3F);
            tls_reg_write32(HR_UART0_TX_WIN, '\r');
        }
        while (tls_reg_read32(HR_UART0_FIFO_STATUS) & 0x3F);
        tls_reg_write32(HR_UART0_TX_WIN, (char)ch);
    } else if (printf_port == 1) {
        if (ch == '\n') {
            while (tls_reg_read32(HR_UART1_FIFO_STATUS) & 0x3F);
            tls_reg_write32(HR_UART1_TX_WIN, '\r');
        }
        while (tls_reg_read32(HR_UART1_FIFO_STATUS) & 0x3F);
        tls_reg_write32(HR_UART1_TX_WIN, (char)ch);
    }
    return ch;
}

int fputc(int ch, FILE *stream)
{
    (void)stream;
    sendchar(ch);
    return 0;
}

#if 1 // defined(__MINILIBC__)
int fgetc(FILE *stream)
{
    (void)stream;

    return 0;
}
#endif

#if 1 // defined(_NEWLIB_VERSION_H__)
int _write_r(void *r, int file, const void *ptr, size_t len)
{
    size_t i;
    char *p;

    p = (char*) ptr;

    for (i = 0; i < len; i++) {
        (void)fputc(*p++, r); /* r: ignore warning */
    }
    return len;
}
#endif

static int __ip2str(unsigned char v4v6, unsigned int *inuint, char *outtxt)
{
    unsigned char j = 0;
    unsigned char h;
    unsigned char m;
    unsigned char l;

    if (4 == v4v6) {
        for (unsigned char i = 0; i < 4; i++) { // 4:loop cap
            unsigned char bit = (*inuint >> (8 * i)) & 0xff; // 8:byte alignment
            h = bit / 100; // 100:byte alignment
            if (h) {
                outtxt[j++] = '0' + h;
            }
            m = (bit % 100) / 10; // 100:byte alignment, 10:byte alignment
            if (m) {
                outtxt[j++] = '0' + m;
            } else {
                if (h) {
                    outtxt[j++] = '0';
                }
            }
            l = (bit % 100) % 10; // 100:byte alignment, 10:byte alignment
            outtxt[j++] = '0' + l;
            outtxt[j++] = '.';
        }
    } else {
        for (unsigned char k = 0; k < 4; k++) { // 4:loop cap
            for (unsigned char i = 0; i < 4; i++) { // 4:loop cap
                m = (*inuint >> (8 * i)) & 0xff; // 8:byte alignment
                h = m >> 4; // 4:byte alignment
                l = m & 0xf;
                if (h > 9) { // 9:byte alignment
                    outtxt[j++] = 'A' + h - 10; // 10:byte alignment
                } else {
                    outtxt[j++]= '0' + h;
                }
                if (l > 9) { // 9:byte alignment
                    outtxt[j++] = 'A' + l - 10; // 10:byte alignment
                } else {
                    outtxt[j++] = '0' + l;
                }
                if ((i % 2) != 0) { // 2:byte alignment
                    outtxt[j++] = ':';
                }
            }
            inuint++;
        }
    }

    outtxt[j - 1] = 0;
    return j - 1;
}

static int __mac2str(unsigned char *inchar, char *outtxt)
{
    unsigned int i;
    for (i = 0; i < 6; i++) { // 6:loop cap
        unsigned char hbit = (*(inchar + i) & 0xf0) >> 4; // 4:byte alignment
        unsigned char lbit = *(inchar + i) & 0x0f;
        if (hbit > 9) { // 9:byte alignment
            outtxt[3 * i] = 'A' + hbit - 10; // 10:byte alignment, 3:byte alignment
        } else {
            outtxt[3 * i]= '0' + hbit; // 3:byte alignment
        }
        if (lbit > 9) { // 9:byte alignment
            outtxt[3 * i + 1] = 'A' + lbit - 10; // 10:byte alignment, 3:byte alignment
        } else {
            outtxt[3 * i + 1] = '0' + lbit; // 3:byte alignment
        }
        outtxt[3 * i + 2] = '-'; // 2:byte alignment, 3:byte alignment
    }

    outtxt[3 * (i - 1) + 2] = 0; // 2:byte alignment, 3:byte alignment

    return 3 * (i - 1) + 2; // 2:byte alignment, 3:byte alignment
}

static inline int digitval(int ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch-'0';
    } else if (ch >= 'A' && ch <= 'Z') {
        return ch-'A' + 10; // 10:byte alignment
    } else if (ch >= 'a' && ch <= 'z') {
        return ch-'a' + 10; // 10:byte alignment
    } else {
        return -1;
    }
}

uintmax_t strntoumax(const char *nptr, char **endptr, int base, size_t n)
{
    int minus = 0;
    uintmax_t v = 0;
    int d;
    int base_tmp = base;
    size_t n_tmp = n;
    const char *nptr_tmp = nptr;

    while (n_tmp && isspace((unsigned char)*nptr_tmp)) {
        nptr_tmp++;
        n_tmp--;
    }

    /* Single optional + or - */
    if (n_tmp && *nptr_tmp == '-') {
        minus = 1;
        nptr_tmp++;
        n_tmp--;
    } else if (n_tmp && *nptr_tmp == '+') {
        nptr_tmp++;
    }

    if (base_tmp == 0) {
        if (n_tmp >= 2 && nptr_tmp[0] == '0' && // 2:byte alignment
            (nptr_tmp[1] == 'x' || nptr_tmp[1] == 'X')) {
                n_tmp -= 2; // 2:byte alignment
                nptr_tmp += 2; // 2:byte alignment
                base_tmp = 16; // 16:byte alignment
        } else if (n_tmp >= 1 && nptr_tmp[0] == '0') {
            n_tmp--;
            nptr_tmp++;
            base_tmp = 8; // 8:byte alignment
        } else {
            base_tmp = 10; // 10:byte alignment
        }
    } else if (base_tmp == 16) { // 16:byte alignment
        if (n_tmp >= 2 && nptr_tmp[0] == '0' &&
            (nptr_tmp[1] == 'x' || nptr_tmp[1] == 'X')) {
                n_tmp -= 2; // 2:byte alignment
                nptr_tmp += 2; // 2:byte alignment
        }
    }

    while (n_tmp && (d = digitval(*nptr_tmp)) >= 0 && d < base_tmp) {
        v = v * base_tmp + d;
        n_tmp--;
        nptr_tmp++;
    }

    if (endptr) {
        *endptr = (char *)nptr_tmp;
    }

    return minus ? -v : v;
}

#ifndef LONG_BIT
#define LONG_BIT (CHAR_BIT*sizeof(long))
#endif

enum flags {
    FL_SPLAT  = 0x01,        /* Drop the value, do not assign */
    FL_INV    = 0x02,        /* Character-set with inverse */
    FL_WIDTH  = 0x04,        /* Field width specified */
    FL_MINUS  = 0x08,        /* Negative number */
};

enum ranks {
    rank_char    = -2,
    rank_short    = -1,
    rank_int     = 0,
    rank_long    = 1,
    rank_longlong    = 2,
    rank_ptr      = INT_MAX    /* Special value used for pointers */
};

#define MIN_RANK    rank_char
#define MAX_RANK    rank_longlong

#define INTMAX_RANK    rank_longlong
#define SIZE_T_RANK    rank_long
#define PTRDIFF_T_RANK    rank_long

enum bail {
    bail_none = 0,        /* No error condition */
    bail_eof,            /* Hit EOF */
    bail_err            /* Conversion mismatch */
};

static inline const char *skipspace(const char *p)
{
    const char *p_tmp = p;
    while (isspace((unsigned char)*p_tmp)) {
        p_tmp++;
    }
    return p_tmp;
}

#undef set_bit
static inline void set_bit(unsigned long *bitmap, unsigned int bit)
{
    bitmap[bit/LONG_BIT] |= 1UL << (bit%LONG_BIT);
}

#undef test_bit
static inline int test_bit(unsigned long *bitmap, unsigned int bit)
{
    return (int)(bitmap[bit/LONG_BIT] >> (bit%LONG_BIT)) & 1;
}

int wm_vsscanf(const char *buffer, const char *format, va_list ap)
{
    const char *p = format;
    char ch;
    const char *q = buffer;
    const char *qq;
    uintmax_t val = 0;
    int rank = rank_int;        /* Default rank */
    unsigned int width = UINT_MAX;
    int base;
    enum flags flags = 0;
    enum {
        st_normal,            /* Ground state */
        st_flags,            /* Special flags */
        st_width,            /* Field width */
        st_modifiers,        /* Length or conversion modifiers */
        st_match_init,        /* Initial state of %[ sequence */
        st_match,            /* Main state of %[ sequence */
        st_match_range,        /* After - in a %[ sequence */
    } state = st_normal;
    char *sarg = NULL;        /* %s %c or %[ string argument */
    enum bail bail = bail_none;
    int sign = 0;
    int converted = 0;        /* Successful conversions */
    unsigned long matchmap[((1 << CHAR_BIT)+(LONG_BIT-1))/LONG_BIT];
    int matchinv = 0;        /* Is match map inverted? */
    unsigned char range_start = 0;

    while ((ch = *p++) && !bail) {
        switch (state) {
            case st_normal:
                if (ch == '%') {
                    state = st_flags;
                    flags = 0;
                    rank = rank_int;
                    width = UINT_MAX;
                } else if (isspace((unsigned char)ch)) {
                    q = skipspace(q);
                } else {
                    if (*q == ch) {
                        q++;
                    } else {
                        bail = bail_err;    /* Match failure */
                    }
                }
                break;

            case st_flags:
                switch (ch) {
                    case '*':
                        flags |= FL_SPLAT;
                        break;
                    case '0' ... '9':
                        width = (ch-'0');
                        state = st_width;
                        flags |= FL_WIDTH;
                        break;
                    default:
                        state = st_modifiers;
                        p--;            /* Process this character again */
                        break;
                }
                break;

            case st_width:
                if (ch >= '0' && ch <= '9') {
                    width = width*10+(ch-'0');
                } else {
                    state = st_modifiers;
                    p--;            /* Process this character again */
                }
                break;
            case st_modifiers:
                switch (ch) {
                /* Length modifiers - nonterminal sequences */
                    case 'h':
                        rank--;            /* Shorter rank */
                        break;
                    case 'l':
                        rank++;            /* Longer rank */
                        break;
                    case 'j':
                        rank = INTMAX_RANK;
                        break;
                    case 'z':
                        rank = SIZE_T_RANK;
                        break;
                    case 't':
                        rank = PTRDIFF_T_RANK;
                        break;
                    case 'L':
                    case 'q':
                        rank = rank_longlong;    /* long double/long long */
                        break;
                    default:
                        /* Output modifiers - terminal sequences */
                        state = st_normal;    /* Next state will be normal */
                        if (rank < MIN_RANK) {   /* Canonicalize rank */
                            rank = MIN_RANK;
                        } else if (rank > MAX_RANK) {
                            rank = MAX_RANK;
                        }

                        switch (ch) {
                            case 'P':        /* Upper case pointer */
                            case 'p':        /* Pointer */
                                rank = rank_ptr;
                                base = 0; sign = 0;
                                goto scan_int;

                            case 'i':        /* Base-independent integer */
                                base = 0; sign = 1;
                                goto scan_int;

                            case 'd':        /* Decimal integer */
                                base = 10; sign = 1;
                                goto scan_int;

                            case 'o':        /* Octal integer */
                                base = 8; sign = 0;
                                goto scan_int;

                            case 'u':        /* Unsigned decimal integer */
                                base = 10; sign = 0;
                                goto scan_int;

                            case 'x':        /* Hexadecimal integer */
                            case 'X':
                                base = 16; sign = 0;
                                goto scan_int;

                            case 'n':        /* Number of characters consumed */
                                val = (q-buffer);
                                goto set_integer;

                                scan_int:
                                    q = skipspace(q);
                                    if (!*q) {
                                        bail = bail_eof;
                                    break;
                                }
                                    val = strntoumax(q, (char **)&qq, base, width);
                                    if (qq == q) {
                                        bail = bail_err;
                                    break;
                                }
                                    q = qq;
                                    converted++;
                                    /* fall through */

                                set_integer:
                                    if (!(flags & FL_SPLAT)) {
                                        switch (rank) {
                                            case rank_char:
                                                *va_arg(ap, unsigned char *) = (unsigned char)val;
                                                break;
                                            case rank_short:
                                                *va_arg(ap, unsigned short *) = (unsigned short)val;
                                                break;
                                            case rank_int:
                                                *va_arg(ap, unsigned int *) = (unsigned int)val;
                                                break;
                                            case rank_long:
                                                *va_arg(ap, unsigned long *) = (unsigned long)val;
                                                break;
                                            case rank_longlong:
                                                *va_arg(ap, unsigned long long *) = (unsigned long long)val;
                                                break;
                                            case rank_ptr:
                                                *va_arg(ap, void **) = (void *)(uintptr_t)val;
                                                break;
                                            default:
                                                break;
                                        }
                                    }
                                    break;

                            case 'c':               /* Character */
                                    width = (flags & FL_WIDTH) ? width : 1; /* Default width == 1 */
                                    sarg = va_arg(ap, char *);
                                    while (width--) {
                                        if (!*q) {
                                            bail = bail_eof;
                                            break;
                                        }
                                        *sarg++ = *q++;
                                    }
                                    if (!bail) {
                                        converted++;
                                    }
                                    break;

                            case 's':               /* String */
                                {
                                    char *sp;
                                    sp = sarg = va_arg(ap, char *);
                                    while (width-- && *q && !isspace((unsigned char)*q)) {
                                        *sp++ = *q++;
                                    }
                                    if (sarg != sp) {
                                        *sp = '\0';    /* Terminate output */
                                        converted++;
                                    } else {
                                        bail = bail_eof;
                                    }
                                }
                                break;

                            case 'f':               /* float */
                                {
                                    float *vp = (float *) va_arg(ap, float *);
                                    const char *vpq = q;
                                    *vp = strtof(vpq, (char **)&q);
                                    if (vpq != q) {
                                        converted++;
                                    } else {
                                        bail = bail_err;
                                    }
                                }
                                break;
                            case 'g':               /* double */
                                {
                                    double *vp = (double *) va_arg(ap, double *);
                                    const char *vpq = q;
                                    *vp = strtod(vpq, (char **)&q);
                                    if (vpq != q) {
                                        converted++;
                                    } else {
                                        bail = bail_err;
                                    }
                                }
                                break;

                            case '[':        /* Character range */
                                sarg = va_arg(ap, char *);
                                state = st_match_init;
                                matchinv = 0;
                                memset_s(matchmap, sizeof(matchmap), 0, sizeof matchmap);
                                break;

                            case '%':        /* %% sequence */
                                if (*q == '%') {
                                    q++;
                                } else {
                                    bail = bail_err;
                                }
                                break;

                            default:        /* Anything else */
                                bail = bail_err;    /* Unknown sequence */
                                break;
                            }
                }
                break;

            case st_match_init:        /* Initial state for %[ match */
                if (ch == '^' && !(flags & FL_INV)) {
                    matchinv = 1;
                } else {
                    set_bit(matchmap, (unsigned char)ch);
                    state = st_match;
                }
                break;

            case st_match:        /* Main state for %[ match */
                if (ch == ']') {
                    goto match_run;
                } else if (ch == '-') {
                    range_start = (unsigned char)ch;
                    state = st_match_range;
                } else {
                    set_bit(matchmap, (unsigned char)ch);
                }
                break;

            case st_match_range:        /* %[ match after - */
                if (ch == ']') {
                    set_bit(matchmap, (unsigned char)'-'); /* - was last character */
                    goto match_run;
                } else {
                    int i;
                    for (i = range_start ; i < (unsigned char)ch ; i++) {
                        set_bit(matchmap, i);
                    }
                    state = st_match;
                }
                break;

                match_run:            /* Match expression finished */
                    qq = q;
                    while (width && *q && (test_bit(matchmap, (unsigned char)*q)^matchinv)) {
                        *sarg++ = *q++;
                    }
                    if (q != qq) {
                        *sarg = '\0';
                        converted++;
                    } else {
                        bail = *q ? bail_err : bail_eof;
                    }
                    break;
        }
    }

    if (bail == bail_eof && !converted) {
        converted = -1;        /* Return EOF (-1) */
    }

    return converted;
}

#define PRINTF_NTOA_BUFFER_SIZE    32U
#define PRINTF_FTOA_BUFFER_SIZE    32U
#define PRINTF_SUPPORT_FLOAT
#define PRINTF_SUPPORT_EXPONENTIAL
#define PRINTF_DEFAULT_FLOAT_PRECISION  6U
#define PRINTF_MAX_FLOAT  1e9
#define PRINTF_SUPPORT_LONG_LONG
#define PRINTF_SUPPORT_PTRDIFF_T

// import float.h for DBL_MAX
#if defined(PRINTF_SUPPORT_FLOAT)
#include <float.h>
#endif

// internal flag definitions
#define FLAGS_ZEROPAD   (1U <<  0U)
#define FLAGS_LEFT      (1U <<  1U)
#define FLAGS_PLUS      (1U <<  2U)
#define FLAGS_SPACE     (1U <<  3U)
#define FLAGS_HASH      (1U <<  4U)
#define FLAGS_UPPERCASE (1U <<  5U)
#define FLAGS_CHAR      (1U <<  6U)
#define FLAGS_SHORT     (1U <<  7U)
#define FLAGS_LONG      (1U <<  8U)
#define FLAGS_LONG_LONG (1U <<  9U)
#define FLAGS_PRECISION (1U << 10U)
#define FLAGS_ADAPT_EXP (1U << 11U)

// output function type
typedef void (*out_fct_type)(char character, void* buffer, size_t idx, size_t maxlen);

// internal buffer output
static inline void _out_buffer(char character, void* buffer, size_t idx, size_t maxlen)
{
    if (idx < maxlen) {
        ((char*)buffer)[idx] = character;
    }
}

static inline void _out_uart(char character, void* buffer, size_t idx, size_t maxlen)
{
    _write_r(NULL, 0, &character, 1);
}

// internal null output
static inline void _out_null(char character, void* buffer, size_t idx, size_t maxlen)
{
    (void)character;
    (void)buffer;
    (void)idx;
    (void)maxlen;
}

// internal secure strlen
// \return The length of the string (excluding the terminating 0) limited by 'maxsize'
static inline unsigned int _strnlen_s(const char* str, size_t maxsize)
{
    const char* s;
    size_t maxsize_tmp = maxsize;
    for (s = str; *s && maxsize_tmp--; ++s) {
    }
    return (unsigned int)(s - str);
}

// internal test if char is a digit (0-9)
// \return true if char is a digit
static inline bool _is_digit(char ch)
{
    return (ch >= '0') && (ch <= '9');
}

// internal ASCII string to unsigned int conversion
static unsigned int _atoi(const char** str)
{
    unsigned int i = 0U;
    while (_is_digit(**str)) {
        i = i * 10U + (unsigned int)(*((*str)++) - '0');
    }
    return i;
}

// output the specified string in reverse, taking care of any zero-padding
static size_t _out_rev(out_fct_type out, char* buffer, size_t idx, size_t maxlen,
                       const char* buf, size_t len, unsigned int width, unsigned int flags)
{
    const size_t start_idx = idx;
    size_t idx_tmp = idx;
    size_t len_tmp = len;

    // pad spaces up to given width
    if (!(flags & FLAGS_LEFT) && !(flags & FLAGS_ZEROPAD)) {
        for (size_t i = len_tmp; i < width; i++) {
            out(' ', buffer, idx_tmp++, maxlen);
        }
    }

  // reverse string
    while (len_tmp) {
        out(buf[--len_tmp], buffer, idx_tmp++, maxlen);
    }

  // append pad spaces up to given width
    if (flags & FLAGS_LEFT) {
        while (idx_tmp - start_idx < width) {
            out(' ', buffer, idx_tmp++, maxlen);
        }
    }

    return idx_tmp;
}

// internal itoa format
static size_t _ntoa_format(out_fct_type out, char* buffer, size_t idx, size_t maxlen,
                           char* buf, size_t len, bool negative, unsigned int base,
                           unsigned int prec, unsigned int width, unsigned int flags)
{
    size_t len_tmp = len;
    unsigned int width_tmp = width;
  // pad leading zeros
    if (!(flags & FLAGS_LEFT)) {
        if (width_tmp && (flags & FLAGS_ZEROPAD) && (negative || (flags & (FLAGS_PLUS | FLAGS_SPACE)))) {
            width_tmp--;
        }
        while ((len_tmp < prec) && (len_tmp < PRINTF_NTOA_BUFFER_SIZE)) {
            buf[len_tmp++] = '0';
        }
        while ((flags & FLAGS_ZEROPAD) && (len_tmp < width_tmp) && (len_tmp < PRINTF_NTOA_BUFFER_SIZE)) {
            buf[len_tmp++] = '0';
        }
    }

  // handle hash
    if (flags & FLAGS_HASH) {
        if (!(flags & FLAGS_PRECISION) && len_tmp && ((len_tmp == prec) || (len_tmp == width_tmp))) {
            len_tmp--;
        if (len_tmp && (base == 16U)) {
            len_tmp--;
        }
        }
        if ((base == 16U) && !(flags & FLAGS_UPPERCASE) && (len_tmp < PRINTF_NTOA_BUFFER_SIZE)) {
            buf[len_tmp++] = 'x';
        } else if ((base == 16U) && (flags & FLAGS_UPPERCASE) && (len_tmp < PRINTF_NTOA_BUFFER_SIZE)) {
            buf[len_tmp++] = 'X';
        } else if ((base == 2U) && (len_tmp < PRINTF_NTOA_BUFFER_SIZE)) {
            buf[len_tmp++] = 'b';
        }
        if (len_tmp < PRINTF_NTOA_BUFFER_SIZE) {
            buf[len_tmp++] = '0';
        }
    }

    if (len_tmp < PRINTF_NTOA_BUFFER_SIZE) {
        if (negative) {
            buf[len_tmp++] = '-';
        } else if (flags & FLAGS_PLUS) {
            buf[len_tmp++] = '+';  // ignore the space if the '+' exists
        } else if (flags & FLAGS_SPACE) {
            buf[len_tmp++] = ' ';
        }
    }

    return _out_rev(out, buffer, idx, maxlen, buf, len_tmp, width_tmp, flags);
}

// internal itoa for 'long' type
static size_t _ntoa_long(out_fct_type out, char* buffer, size_t idx, size_t maxlen,
                         unsigned long value, bool negative, unsigned long base,
                         unsigned int prec, unsigned int width, unsigned int flags)
{
    unsigned int flags_tmp = flags;
    unsigned long value_tmp = value;
    char buf[PRINTF_NTOA_BUFFER_SIZE];
    size_t len = 0U;

    // no hash for 0 values
    if (!value_tmp) {
        flags_tmp &= ~FLAGS_HASH;
    }

    // write if precision != 0 and value is != 0
    if (!(flags_tmp & FLAGS_PRECISION) || value_tmp) {
        do {
            if (base == 0) {
            }
            const char digit = (char)(value_tmp % base);
            buf[len++] = digit < 10 ? '0' + digit : ((flags_tmp & FLAGS_UPPERCASE) ? 'A' : 'a') + digit - 10;
            if (value_tmp == 0) {
            }
            value_tmp /= base;
        } while (value_tmp && (len < PRINTF_NTOA_BUFFER_SIZE));
    }

    return _ntoa_format(out, buffer, idx, maxlen, buf, len, negative, (unsigned int)base, prec, width, flags_tmp);
}

// internal itoa for 'long long' type
#if defined(PRINTF_SUPPORT_LONG_LONG)
static size_t _ntoa_long_long(out_fct_type out, char* buffer, size_t idx, size_t maxlen,
                              unsigned long long value, bool negative, unsigned long long base,
                              unsigned int prec, unsigned int width, unsigned int flags)
{
    unsigned int flags_tmp = flags;
    unsigned long value_tmp = value;
    char buf[PRINTF_NTOA_BUFFER_SIZE];
    size_t len = 0U;

    // no hash for 0 values
    if (!value_tmp) {
        flags_tmp &= ~FLAGS_HASH;
    }

    // write if precision != 0 and value is != 0
    if (!(flags_tmp & FLAGS_PRECISION) || value_tmp) {
        do {
            if (base == 0) {
            }
            const char digit = (char)(value_tmp % base);
            buf[len++] = (digit < 10) ? ('0' + digit) : (((flags_tmp & FLAGS_UPPERCASE) ? 'A' : 'a') + digit - 10);
            if (value_tmp == 0) {
            }
            value_tmp /= base;
        } while (value_tmp && (len < PRINTF_NTOA_BUFFER_SIZE));
    }

    return _ntoa_format(out, buffer, idx, maxlen, buf, len, negative, (unsigned int)base, prec, width, flags_tmp);
}
#endif  // PRINTF_SUPPORT_LONG_LONG

#if defined(PRINTF_SUPPORT_FLOAT)

#if defined(PRINTF_SUPPORT_EXPONENTIAL)
// forward declaration so that _ftoa can switch to exp notation for values > PRINTF_MAX_FLOAT
static size_t _etoa(out_fct_type out, char* buffer, size_t idx, size_t maxlen,
                    double value, unsigned int prec, unsigned int width, unsigned int flags);
#endif

// internal ftoa for fixed decimal floating point
static size_t _ftoa(out_fct_type out, char* buffer, size_t idx, size_t maxlen,
                    double value, unsigned int prec, unsigned int width, unsigned int flags)
{
    unsigned int prec_tmp = prec;
    char buf[PRINTF_FTOA_BUFFER_SIZE];
    size_t len  = 0U;
    double diff = 0.0;
    double value_tmp = value;
    unsigned int width_tmp = width;

    // powers of 10
    static const double pow10[] = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000 };

    // test for special values
    if (value_tmp != value_tmp) {
        return _out_rev(out, buffer, idx, maxlen, "nan", 3, width_tmp, flags); // 3:len
    }
    if (value_tmp < -DBL_MAX) {
        return _out_rev(out, buffer, idx, maxlen, "fni-", 4, width_tmp, flags); // 4:len
    }
    if (value_tmp > DBL_MAX) {
        return _out_rev(out, buffer, idx, maxlen, (flags & FLAGS_PLUS) ? "fni+" : "fni",
            (flags & FLAGS_PLUS) ? 4U : 3U, width_tmp, flags);
    }

    // test for very large values
    // standard printf behavior is to print EVERY whole number digit --
    // which could be 100s of characters overflowing your buffers == bad
    if ((value_tmp > PRINTF_MAX_FLOAT) || (value_tmp < -PRINTF_MAX_FLOAT)) {
#if defined(PRINTF_SUPPORT_EXPONENTIAL)
        return _etoa(out, buffer, idx, maxlen, value_tmp, prec_tmp, width_tmp, flags);
#else
        return 0U;
#endif
    }
    // test for negative
    bool negative = false;
    if (value_tmp < 0) {
        negative = true;
        value_tmp = 0 - value_tmp;
    }

    // set default precision, if not set explicitly
    if (!(flags & FLAGS_PRECISION)) {
        prec_tmp = PRINTF_DEFAULT_FLOAT_PRECISION;
    }
    // limit precision to 9, cause a prec >= 10 can lead to overflow errors
    while ((len < PRINTF_FTOA_BUFFER_SIZE) && (prec_tmp > 9U)) {
        buf[len++] = '0';
        prec_tmp--;
    }

    int whole = (int)value_tmp;
    double tmp = (value_tmp - whole) * pow10[prec_tmp];
    unsigned long frac = (unsigned long)tmp;
    diff = tmp - frac;

    if (diff > 0.5) {
        ++frac;
        // handle rollover, e.g. case 0.99 with prec 1 is 1.0
        if (frac >= pow10[prec_tmp]) {
            frac = 0;
            ++whole;
        }
    } else if (diff < 0.5) {
    } else if ((frac == 0U) || (frac & 1U)) {
        // if halfway, round up if odd OR if last digit is 0
        ++frac;
    }

    if (prec_tmp == 0U) {
        diff = value_tmp - (double)whole;
        if ((diff > 0.5) && (whole & 1)) {
            // exactly 0.5 and ODD, then round up
            // 1.5 -> 2, but 2.5 -> 2
            ++whole;
        }
    } else {
        unsigned int count = prec_tmp;
        // now do fractional part, as an unsigned number
        while (len < PRINTF_FTOA_BUFFER_SIZE) {
            --count;
            buf[len++] = (char)(48U + (frac % 10U));
            if (!(frac /= 10U)) {
                break;
            }
        }
        // add extra 0s
        while ((len < PRINTF_FTOA_BUFFER_SIZE) && (count-- > 0U)) {
            buf[len++] = '0';
        }
        if (len < PRINTF_FTOA_BUFFER_SIZE) {
            // add decimal
            buf[len++] = '.';
        }
    }

    // do whole part, number is reversed
    while (len < PRINTF_FTOA_BUFFER_SIZE) {
        buf[len++] = (char)(48 + (whole % 10));
        if (!(whole /= 10)) {
            break;
        }
    }

    // pad leading zeros
    if (!(flags & FLAGS_LEFT) && (flags & FLAGS_ZEROPAD)) {
        if (width_tmp && (negative || (flags & (FLAGS_PLUS | FLAGS_SPACE)))) {
            width_tmp--;
        }
        while ((len < width_tmp) && (len < PRINTF_FTOA_BUFFER_SIZE)) {
            buf[len++] = '0';
        }
    }

    if (len < PRINTF_FTOA_BUFFER_SIZE) {
        if (negative) {
            buf[len++] = '-';
        } else if (flags & FLAGS_PLUS) {
            buf[len++] = '+';  // ignore the space if the '+' exists
        } else if (flags & FLAGS_SPACE) {
            buf[len++] = ' ';
        }
    }

    return _out_rev(out, buffer, idx, maxlen, buf, len, width_tmp, flags);
}

#if defined(PRINTF_SUPPORT_EXPONENTIAL)
// internal ftoa variant for exponential floating-point type, contributed by Martijn Jasperse <m.jasperse@gmail.com>
static size_t _etoa(out_fct_type out, char* buffer, size_t idx, size_t maxlen, double value,
                    unsigned int prec, unsigned int width, unsigned int flags)
{
    unsigned int prec_tmp = prec;
    double value_tmp = value;
    unsigned int flags_tmp = flags;
    size_t idx_tmp = idx;
    char* buffer_tmp = buffer;
    // check for NaN and special values
    if ((value_tmp != value_tmp) || (value_tmp > DBL_MAX) || (value_tmp < -DBL_MAX)) {
        return _ftoa(out, buffer_tmp, idx_tmp, maxlen, value_tmp, prec_tmp, width, flags_tmp);
    }

    // determine the sign
    const bool negative = value_tmp < 0;
    if (negative) {
        value_tmp = -value_tmp;
    }

    // default precision
    if (!(flags_tmp & FLAGS_PRECISION)) {
        prec_tmp = PRINTF_DEFAULT_FLOAT_PRECISION;
    }

    // determine the decimal exponent
    // based on the algorithm by David Gay (https:// www.ampl.com/netlib/fp/dtoa.c)
    union {
        uint64_t U;
        double   F;
    } conv;

    conv.F = value_tmp;
    int exp2 = (int)((conv.U >> 52U) & 0x07FFU) - 1023;           // effectively log2
    conv.U = (conv.U & ((1ULL << 52U) - 1U)) | (1023ULL << 52U);  // drop the exponent so conv.F is now in [1,2)
    // now approximate log10 from the log2 integer part and an expansion of ln around 1.5
    int expval = (int)(0.1760912590558 + exp2 * 0.301029995663981 + (conv.F - 1.5) * 0.289529654602168);
    // now we want to compute 10^expval but we want to be sure it won't overflow
    exp2 = (int)(expval * 3.321928094887362 + 0.5);
    const double z  = expval * 2.302585092994046 - exp2 * 0.6931471805599453;
    const double z2 = z * z;
    conv.U = (uint64_t)(exp2 + 1023) << 52U;
    /* compute exp(z) using continued fractions,
     * see https:// en.wikipedia.org/wiki/Exponential_function#Continued_fractions_for_ex
     */
    conv.F *= 1 + 2 * z / (2 - z + (z2 / (6 + // 2:byte alignment, 6:byte alignment
        (z2 / (10 + z2 / 14))))); // 10:byte alignment, 14:byte alignment
    // correct for rounding errors
    if (value_tmp < conv.F) {
        expval--;
        conv.F /= 10; // 10:byte alignment
    }

    // the exponent format is "%+03d" and largest value is "307", so set aside 4-5 characters
    unsigned int minwidth = ((expval < 100) && (expval > -100)) ? 4U : 5U;

    // in "%g" mode, "prec" is the number of *significant figures* not decimals
    if (flags_tmp & FLAGS_ADAPT_EXP) {
      // do we want to fall-back to "%f" mode?
        if ((value_tmp >= 1e-4) && (value_tmp < 1e6)) {
            if ((int)prec_tmp > expval) {
                prec_tmp = (unsigned)((int)prec_tmp - expval - 1);
            } else {
                prec_tmp = 0;
            }
            flags_tmp |= FLAGS_PRECISION;   // make sure _ftoa respects precision
            // no characters in exponent
            minwidth = 0U;
            expval   = 0;
        } else {
          // we use one sigfig for the whole part
            if ((prec_tmp > 0) && (flags_tmp & FLAGS_PRECISION)) {
                --prec_tmp;
            }
        }
    }

    // will everything fit?
    unsigned int fwidth = width;
    if (width > minwidth) {
        // we didn't fall-back so subtract the characters required for the exponent
        fwidth -= minwidth;
    } else {
        // not enough characters, so go back to default sizing
        fwidth = 0U;
    }
    if ((flags_tmp & FLAGS_LEFT) && minwidth) {
        // if we're padding on the right, DON'T pad the floating part
        fwidth = 0U;
    }

    // rescale the float value
    if (expval) {
        value_tmp /= conv.F;
    }

    // output the floating part
    const size_t start_idx = idx_tmp;
    idx_tmp = _ftoa(out, buffer_tmp, idx_tmp, maxlen,
        negative ? -value_tmp : value_tmp, prec_tmp, fwidth, flags_tmp & ~FLAGS_ADAPT_EXP);

    // output the exponent part
    if (!prec_tmp && minwidth) {
        // output the exponential symbol
        out((flags_tmp & FLAGS_UPPERCASE) ? 'E' : 'e', buffer_tmp, idx_tmp++, maxlen);
        // output the exponent value
        idx_tmp = _ntoa_long(out, buffer_tmp, idx_tmp, maxlen, (expval < 0) ? -expval : expval,
            expval < 0, 10, 0, minwidth-1, FLAGS_ZEROPAD | FLAGS_PLUS);
        // might need to right-pad spaces
        if (flags_tmp & FLAGS_LEFT) {
            while (idx_tmp - start_idx < width) {
                out(' ', buffer_tmp, idx_tmp++, maxlen);
            }
        }
    }
    return idx_tmp;
}
#endif  // PRINTF_SUPPORT_EXPONENTIAL
#endif  // PRINTF_SUPPORT_FLOAT

// internal vsnprintf
static int _vsnprintf(out_fct_type out, char* buffer, const size_t maxlen, const char* format, va_list va)
{
    unsigned int flags, width, precision, n;
    size_t idx = 0U;
    out_fct_type out_tmp = out;
    const char* format_tmp = format;

    if (!buffer) {
        // use null output function
        out_tmp = _out_null;
    }

    while (*format_tmp) {
        // format specifier?  %[flags][width][.precision][length]
        if (*format_tmp != '%') {
            // no
            out_tmp(*format_tmp, buffer, idx++, maxlen);
            format_tmp++;
            continue;
        } else {
            // yes, evaluate it
            format_tmp++;
        }

        // evaluate flags
        flags = 0U;
        do {
            switch (*format_tmp) {
                case '0': flags |= FLAGS_ZEROPAD; format_tmp++; n = 1U; break;
                case '-': flags |= FLAGS_LEFT;    format_tmp++; n = 1U; break;
                case '+': flags |= FLAGS_PLUS;    format_tmp++; n = 1U; break;
                case ' ': flags |= FLAGS_SPACE;   format_tmp++; n = 1U; break;
                case '#': flags |= FLAGS_HASH;    format_tmp++; n = 1U; break;
                default :                                   n = 0U; break;
            }
        } while (n);

        // evaluate width field
        width = 0U;
        if (_is_digit(*format_tmp)) {
            width = _atoi(&format_tmp);
        } else if (*format_tmp == '*') {
            const int w = va_arg(va, int);
            if (w < 0) {
                flags |= FLAGS_LEFT;    // reverse padding
                width = (unsigned int)-w;
            } else {
                width = (unsigned int)w;
            }
            format_tmp++;
        }

        // evaluate precision field
        precision = 0U;
        if (*format_tmp == '.') {
            flags |= FLAGS_PRECISION;
            format_tmp++;
            if (_is_digit(*format_tmp)) {
                precision = _atoi(&format_tmp);
            } else if (*format_tmp == '*') {
                const int prec = (int)va_arg(va, int);
                precision = prec > 0 ? (unsigned int)prec : 0U;
                format_tmp++;
            }
        }

        // evaluate length field
        switch (*format_tmp) {
            case 'l' :
                flags |= FLAGS_LONG;
                format_tmp++;
                if (*format_tmp == 'l') {
                    flags |= FLAGS_LONG_LONG;
                    format_tmp++;
                }
                break;
            case 'h' :
                flags |= FLAGS_SHORT;
                format_tmp++;
                if (*format_tmp == 'h') {
                    flags |= FLAGS_CHAR;
                    format_tmp++;
                }
                break;
#if defined(PRINTF_SUPPORT_PTRDIFF_T)
            case 't' :
                flags |= (sizeof(ptrdiff_t) == sizeof(long) ? FLAGS_LONG : FLAGS_LONG_LONG);
                format_tmp++;
                break;
#endif
            case 'j' :
                flags |= (sizeof(intmax_t) == sizeof(long) ? FLAGS_LONG : FLAGS_LONG_LONG);
                format_tmp++;
                break;
            case 'z' :
                flags |= (sizeof(size_t) == sizeof(long) ? FLAGS_LONG : FLAGS_LONG_LONG);
                format_tmp++;
                break;
            default :
                break;
        }

        // evaluate specifier
        switch (*format_tmp) {
            case 'd' :
            case 'i' :
            case 'u' :
            case 'x' :
            case 'X' :
            case 'o' :
            case 'b' : {
                // set the base
                unsigned int base;
                if (*format_tmp == 'x' || *format_tmp == 'X') {
                    base = 16U;
                } else if (*format_tmp == 'o') {
                    base =  8U;
                } else if (*format_tmp == 'b') {
                    base =  2U;
                } else {
                    base = 10U;
                    flags &= ~FLAGS_HASH;   // no hash for dec format
                }
                // uppercase
                if (*format_tmp == 'X') {
                    flags |= FLAGS_UPPERCASE;
                }

                // no plus or space flag for u, x, X, o, b
                if ((*format_tmp != 'i') && (*format_tmp != 'd')) {
                    flags &= ~(FLAGS_PLUS | FLAGS_SPACE);
                }

                // ignore '0' flag when precision is given
                if (flags & FLAGS_PRECISION) {
                    flags &= ~FLAGS_ZEROPAD;
                }

                // convert the integer
                if ((*format_tmp == 'i') || (*format_tmp == 'd')) {
                  // signed
                    if (flags & FLAGS_LONG_LONG) {
#if defined(PRINTF_SUPPORT_LONG_LONG)
                        const long long value = va_arg(va, long long);
                        idx = _ntoa_long_long(out_tmp, buffer, idx, maxlen,
                                              (unsigned long long)(value > 0 ? value : 0 - value),
                                              value < 0, base, precision, width, flags);
#endif
                    } else if (flags & FLAGS_LONG) {
                        const long value = va_arg(va, long);
                        idx = _ntoa_long(out_tmp, buffer, idx, maxlen, (unsigned long)(value > 0 ? value : 0 - value),
                                         value < 0, base, precision, width, flags);
                    } else {
                        const int value = (flags & FLAGS_CHAR) ? (char)va_arg(va, int) : \
                            (flags & FLAGS_SHORT) ? (short int)va_arg(va, int) : va_arg(va, int);
                        idx = _ntoa_long(out_tmp, buffer, idx, maxlen, (unsigned int)(value > 0 ? value : 0 - value),
                                         value < 0, base, precision, width, flags);
                    }
                } else {
                    // unsigned
                    if (flags & FLAGS_LONG_LONG) {
#if defined(PRINTF_SUPPORT_LONG_LONG)
                        idx = _ntoa_long_long(out_tmp, buffer, idx, maxlen, va_arg(va, unsigned long long),
                                              false, base, precision, width, flags);
#endif
                    } else if (flags & FLAGS_LONG) {
                        idx = _ntoa_long(out_tmp, buffer, idx, maxlen, va_arg(va, unsigned long),
                                         false, base, precision, width, flags);
                    } else {
                        const unsigned int value = (flags & FLAGS_CHAR) ? (unsigned char)va_arg(va, unsigned int) : \
                            (flags & FLAGS_SHORT) ? (unsigned short int)va_arg(va, unsigned int) : \
                            va_arg(va, unsigned int);
                        idx = _ntoa_long(out_tmp, buffer, idx, maxlen, value, false, base, precision, width, flags);
                    }
                }
                format_tmp++;
                break;
            }
#if defined(PRINTF_SUPPORT_FLOAT)
            case 'f' :
            case 'F' :
                if (*format_tmp == 'F') {
                    flags |= FLAGS_UPPERCASE;
                }
                idx = _ftoa(out_tmp, buffer, idx, maxlen, va_arg(va, double), precision, width, flags);
                format_tmp++;
                break;
#if defined(PRINTF_SUPPORT_EXPONENTIAL)
            case 'e':
            case 'E':
            case 'g':
            case 'G':
                if ((*format_tmp == 'g')||(*format_tmp == 'G')) {
                    flags |= FLAGS_ADAPT_EXP;
                }
                if ((*format_tmp == 'E')||(*format_tmp == 'G')) {
                    flags |= FLAGS_UPPERCASE;
                }
                idx = _etoa(out_tmp, buffer, idx, maxlen, va_arg(va, double), precision, width, flags);
                format_tmp++;
                break;
#endif  // PRINTF_SUPPORT_EXPONENTIAL
#endif  // PRINTF_SUPPORT_FLOAT
            case 'c' : {
                unsigned int l = 1U;
                // pre padding
                if (!(flags & FLAGS_LEFT)) {
                    while (l++ < width) {
                        out_tmp(' ', buffer, idx++, maxlen);
                    }
                }
                // char output
                out_tmp((char)va_arg(va, int), buffer, idx++, maxlen);
                // post padding
                if (flags & FLAGS_LEFT) {
                    while (l++ < width) {
                        out_tmp(' ', buffer, idx++, maxlen);
                    }
                }
                format_tmp++;
                break;
            }

            case 's' : {
                const char* p = va_arg(va, char*);
                unsigned int l = _strnlen_s(p, precision ? precision : (size_t)-1);
                // pre padding
                if (flags & FLAGS_PRECISION) {
                    l = (l < precision ? l : precision);
                }
                if (!(flags & FLAGS_LEFT)) {
                    while (l++ < width) {
                        out_tmp(' ', buffer, idx++, maxlen);
                    }
                }
                // string output
                while ((*p != 0) && (!(flags & FLAGS_PRECISION) || precision--)) {
                    out_tmp(*(p++), buffer, idx++, maxlen);
                }
                // post padding
                if (flags & FLAGS_LEFT) {
                    while (l++ < width) {
                        out_tmp(' ', buffer, idx++, maxlen);
                    }
                }
                format_tmp++;
                break;
            }

            case 'p' : {
                width = sizeof(void*) * 2U;
                flags |= FLAGS_ZEROPAD | FLAGS_UPPERCASE;
#if defined(PRINTF_SUPPORT_LONG_LONG)
                bool is_ll = false;
                if (sizeof(uintptr_t) == sizeof(long long)) {
                    is_ll = true;
                }
                if (is_ll) {
                    idx = _ntoa_long_long(out_tmp, buffer, idx, maxlen, (uintptr_t)va_arg(va, void*),
                                          false, 16U, precision, width, flags);
                } else {
#endif
                idx = _ntoa_long(out_tmp, buffer, idx, maxlen, (unsigned long)((uintptr_t)va_arg(va, void*)),
                                 false, 16U, precision, width, flags);
#if defined(PRINTF_SUPPORT_LONG_LONG)
                }
#endif
                format_tmp++;
                break;
            }

            case 'M' : {
                const char* p = va_arg(va, char*);
                char store[40];
                unsigned int l = __mac2str((unsigned char *)p, store);
                const char* pstr = &store[0];
                // pre padding
                if (flags & FLAGS_PRECISION) {
                    l = (l < precision ? l : precision);
                }
                if (!(flags & FLAGS_LEFT)) {
                    while (l++ < width) {
                        out_tmp(' ', buffer, idx++, maxlen);
                    }
                }
                // string output
                while ((*pstr != 0) && (!(flags & FLAGS_PRECISION) || precision--)) {
                    out_tmp(*(pstr++), buffer, idx++, maxlen);
                }
                // post padding
                if (flags & FLAGS_LEFT) {
                    while (l++ < width) {
                        out_tmp(' ', buffer, idx++, maxlen);
                    }
                }
                format_tmp++;
                break;
            }
            case 'v' : {
                uint32_t ipv4 = va_arg(va, uint32_t);
                char store[40];
                unsigned int l = __ip2str(4, &ipv4, store);
                const char* pstr = &store[0];
                // pre padding
                if (flags & FLAGS_PRECISION) {
                    l = (l < precision ? l : precision);
                }
                if (!(flags & FLAGS_LEFT)) {
                    while (l++ < width) {
                        out_tmp(' ', buffer, idx++, maxlen);
                    }
                }
                // string output
                while ((*pstr != 0) && (!(flags & FLAGS_PRECISION) || precision--)) {
                    out_tmp(*(pstr++), buffer, idx++, maxlen);
                }
                // post padding
                if (flags & FLAGS_LEFT) {
                    while (l++ < width) {
                        out_tmp(' ', buffer, idx++, maxlen);
                    }
                }
                format_tmp++;
                break;
            }
            case 'V' : {
                char *ipv6 = va_arg(va, char*);
                char store[40];
                unsigned int l = __ip2str(6, (unsigned int *)ipv6, store);
                const char* pstr = &store[0];
                // pre padding
                if (flags & FLAGS_PRECISION) {
                    l = (l < precision ? l : precision);
                }
                if (!(flags & FLAGS_LEFT)) {
                    while (l++ < width) {
                        out_tmp(' ', buffer, idx++, maxlen);
                    }
                }
                // string output
                while ((*pstr != 0) && (!(flags & FLAGS_PRECISION) || precision--)) {
                    out_tmp(*(pstr++), buffer, idx++, maxlen);
                }
                // post padding
                if (flags & FLAGS_LEFT) {
                    while (l++ < width) {
                        out_tmp(' ', buffer, idx++, maxlen);
                    }
                }
                format_tmp++;
                break;
            }

            case '%' :
                out_tmp('%', buffer, idx++, maxlen);
                format_tmp++;
                break;

            default :
                out_tmp(*format_tmp, buffer, idx++, maxlen);
                format_tmp++;
                break;
        }
    }

    // termination
    out_tmp((char)0, buffer, idx < maxlen ? idx : maxlen - 1U, maxlen);

    // return written chars without terminating \0
    return (int)idx;
}

int wm_vsnprintf(char* buffer, size_t count, const char* format, va_list va)
{
    return _vsnprintf(_out_buffer, buffer, count, format, va);
}

#if defined(TLS_OS_LITEOS) && TLS_OS_LITEOS
int printf(const char *restrict fmt, ...)
{
    va_list args;
    size_t length;

    va_start(args, fmt);
    length = _vsnprintf(_out_uart, (char*)fmt, (size_t) - 1, fmt, args);
    va_end(args);

    return length;
}
#endif

int wm_printf(const char *fmt, ...)
{
    va_list args;
    size_t length;

    va_start(args, fmt);
    length = _vsnprintf(_out_uart, (char*)fmt, (size_t) - 1, fmt, args);
    va_end(args);

    return length;
}

int wm_vprintf(const char *fmt, va_list arg_ptr)
{
    size_t length;

    length = _vsnprintf(_out_uart, (char*)fmt, (size_t) - 1, fmt, arg_ptr);

    return length;
}

#if 1 // defined(_NEWLIB_VERSION_H__)
 __attribute__((__weak__)) int sscanf(const char *str, const char *format, ...) /* bug: replace 3.10.21 newlib */
{
    va_list args;
    int i;

    va_start(args, format);
    i = wm_vsscanf(str, format, args);
    va_end(args);

    return i;
}

__attribute__((__weak__)) int __cskyvscanfsscanf(const char *str, const char *format, ...)
{
    va_list args;
    int i;

    va_start(args, format);
    i = wm_vsscanf(str, format, args);
    va_end(args);

    return i;
}

__attribute__((__weak__)) int __cskyvprintfsprintf(char *str, const char *format, ...)
{
    va_list ap;
    int i;

    va_start(ap, format);
    i = wm_vsnprintf(str, (size_t) - 1, format, ap);
    va_end(ap);

    return i;
}

__attribute__((__weak__)) int __cskyvprintfsnprintf(char *str, size_t size, const char *format, ...)
{
    va_list ap;
    int i;

    va_start(ap, format);
    i = wm_vsnprintf(str, size, format, ap);
    va_end(ap);

    return i;
}

__attribute__((__weak__)) int __cskyvprintfvsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    return wm_vsnprintf(str, size, format, ap);
}

__attribute__((__weak__)) int __cskyvprintfvsprintf(char *str, const char *format, va_list ap)
{
    return wm_vsnprintf(str, (size_t) - 1, format, ap);
}

int __cskyvprintfprintf(const char *fmt, ...) __attribute__((__weak__, alias("wm_printf")));

__attribute__((__weak__)) void __assert_fail(const char *file,
    int line,
    const char *func,
    const char *failedexpr)
{
    wm_printf("assertion \"%s\" failed: file \"%s\", line %d%s%s\r\n",
              failedexpr, file, line,
              func ? ", function: " : "", func ? func : "");
    while (1) {
    }
}

/* For CPP type used, you first call this function in main entry */
extern int __dtor_end__;
extern int __ctor_end__;
extern int __ctor_start__;
typedef void (*func_ptr)(void);
__attribute__((__weak__)) void cxx_system_init(void)
{
    func_ptr *p;
    for (p = (func_ptr *)&__ctor_end__ -1; p >= (func_ptr *)&__ctor_start__; p--) {
        (*p)();
    }
}
#endif