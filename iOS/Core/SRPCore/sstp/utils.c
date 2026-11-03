
#include "sstp/utils.h"
#include <sys/time.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <openssl/err.h>

#define lwip_isdigit(c)           isdigit((unsigned char)(c))

int64_t x_socks_system_time_mills(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}


static int UV_EINVAL = -22;
static int UV_EAFNOSUPPORT = -47;
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define UV__INET6_ADDRSTRLEN        46

static int inet_pton4(const char *src, unsigned char *dst) {
    static const char digits[] = "0123456789";
    int saw_digit, octets, ch;
    unsigned char tmp[sizeof(struct in_addr)], *tp;
    
    saw_digit = 0;
    octets = 0;
    *(tp = tmp) = 0;
    while ((ch = *src++) != '\0') {
        const char *pch;
        
        if ((pch = strchr(digits, ch)) != NULL) {
            unsigned int nw = *tp * 10 + (pch - digits);
            
            if (saw_digit && *tp == 0)
                return UV_EINVAL;
            if (nw > 255)
                return UV_EINVAL;
            *tp = nw;
            if (!saw_digit) {
                if (++octets > 4)
                    return UV_EINVAL;
                saw_digit = 1;
            }
        } else if (ch == '.' && saw_digit) {
            if (octets == 4)
                return UV_EINVAL;
            *++tp = 0;
            saw_digit = 0;
        } else
            return UV_EINVAL;
    }
    if (octets < 4)
        return UV_EINVAL;
    memcpy(dst, tmp, sizeof(struct in_addr));
    return 0;
}


static int inet_pton6(const char *src, unsigned char *dst) {
    static const char xdigits_l[] = "0123456789abcdef",
    xdigits_u[] = "0123456789ABCDEF";
    unsigned char tmp[sizeof(struct in6_addr)], *tp, *endp, *colonp;
    const char *xdigits, *curtok;
    int ch, seen_xdigits;
    unsigned int val;
    
    memset((tp = tmp), '\0', sizeof tmp);
    endp = tp + sizeof tmp;
    colonp = NULL;
    /* Leading :: requires some special handling. */
    if (*src == ':')
        if (*++src != ':')
            return UV_EINVAL;
    curtok = src;
    seen_xdigits = 0;
    val = 0;
    while ((ch = *src++) != '\0') {
        const char *pch;
        
        if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
            pch = strchr((xdigits = xdigits_u), ch);
        if (pch != NULL) {
            val <<= 4;
            val |= (pch - xdigits);
            if (++seen_xdigits > 4)
                return UV_EINVAL;
            continue;
        }
        if (ch == ':') {
            curtok = src;
            if (!seen_xdigits) {
                if (colonp)
                    return UV_EINVAL;
                colonp = tp;
                continue;
            } else if (*src == '\0') {
                return UV_EINVAL;
            }
            if (tp + sizeof(uint16_t) > endp)
                return UV_EINVAL;
            *tp++ = (unsigned char) (val >> 8) & 0xff;
            *tp++ = (unsigned char) val & 0xff;
            seen_xdigits = 0;
            val = 0;
            continue;
        }
        if (ch == '.' && ((tp + sizeof(struct in_addr)) <= endp)) {
            int err = inet_pton4(curtok, tp);
            if (err == 0) {
                tp += sizeof(struct in_addr);
                seen_xdigits = 0;
                break;  /*%< '\\0' was seen by inet_pton4(). */
            }
        }
        return UV_EINVAL;
    }
    if (seen_xdigits) {
        if (tp + sizeof(uint16_t) > endp)
            return UV_EINVAL;
        *tp++ = (unsigned char) (val >> 8) & 0xff;
        *tp++ = (unsigned char) val & 0xff;
    }
    if (colonp != NULL) {
        /*
         * Since some memmove()'s erroneously fail to handle
         * overlapping regions, we'll do the shift by hand.
         */
        const int n = tp - colonp;
        int i;
        
        if (tp == endp)
            return UV_EINVAL;
        for (i = 1; i <= n; i++) {
            endp[- i] = colonp[n - i];
            colonp[n - i] = 0;
        }
        tp = endp;
    }
    if (tp != endp)
        return UV_EINVAL;
    memcpy(dst, tmp, sizeof tmp);
    return 0;
}


int uv_inet_pton(int af, const char* src, void* dst) {
    if (src == NULL || dst == NULL)
        return UV_EINVAL;
    
    switch (af) {
        case AF_INET:
            return (inet_pton4(src, dst));
        case AF_INET6: {
            int len;
            char tmp[UV__INET6_ADDRSTRLEN], *s, *p;
            s = (char*) src;
            p = strchr(src, '%');
            if (p != NULL) {
                s = tmp;
                len = p - src;
                if (len > UV__INET6_ADDRSTRLEN-1)
                    return UV_EINVAL;
                memcpy(s, src, len);
                s[len] = '\0';
            }
            return inet_pton6(s, dst);
        }
        default:
            return UV_EAFNOSUPPORT;
    }
    /* NOTREACHED */
}

int uv_ip4_addr(const char* ip, int port, struct sockaddr_in* addr) {
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
#ifdef SIN6_LEN
    addr->sin_len = sizeof(*addr);
#endif
    return uv_inet_pton(AF_INET, ip, &(addr->sin_addr.s_addr));
}

void x_print_bytes(uint8_t *buf, int len) {
    for (int i = 0; i < len; i++) {
        if (i == 0) {
            printf("[%d ", buf[i]);
        }
        else if (i < len - 1) {
            printf("%d ", buf[i]);
        }
        else {
            printf("%d]", buf[i]);
        }
    }
    printf("\n");
}

/*
 * ppp_slprintf - format a message into a buffer.  Like sprintf except we
 * also specify the length of the output buffer, and we handle
 * %m (error message), %v (visible string),
 * %q (quoted string), %t (current time) and %I (IP address) formats.
 * Doesn't do floating-point formats.
 * Returns the number of chars put into buf.
 */

static x_log_print_fn __print__ = NULL;

static int ppp_vslprintf(char *buf, int buflen, const char *fmt, va_list args);


static int ppp_slprintf(char *buf, int buflen, const char *fmt, ...) {
    va_list args;
    int n;

    va_start(args, fmt);
    n = ppp_vslprintf(buf, buflen, fmt, args);
    va_end(args);
    return n;
}

void x_set_print_func(x_log_print_fn cn) {
    __print__ = cn;
}

/*
 * ppp_logit - does the hard work for fatal et al.
 */
static void ppp_logit(int level, const char *fmt, va_list args) {
    char buf[1024];
    ppp_vslprintf(buf, sizeof(buf), fmt, args);
    if (__print__) {
        __print__(buf);
    }
}

void x_debug(const char *fmt, ...) {
    /* Debug level only (profile OPTIONS -> Log Level) */
    extern int ss_log_debug_enabled(void);
    if (!ss_log_debug_enabled()) {
        return;
    }
    va_list pvar;
    va_start(pvar, fmt);
    ppp_logit(0, fmt, pvar);
    va_end(pvar);
}

#define OUTCHAR(c)    (buflen > 0? (--buflen, *buf++ = (c)): 0)

static int ppp_vslprintf(char *buf, int buflen, const char *fmt, va_list args) {
    int c, i, n;
    int width, prec, fillch;
    int base, len, neg, quoted;
    unsigned long val = 0;
    const char *f;
    char *str, *buf0;
    const unsigned char *p;
    char num[32];
    time_t t;
    uint32_t ip;
    static char hexchars[] = "0123456789abcdef";
#if PRINTPKT_SUPPORT
    struct buffer_info bufinfo;
#endif /* PRINTPKT_SUPPORT */

    buf0 = buf;
    --buflen;
    while (buflen > 0) {
    for (f = fmt; *f != '%' && *f != 0; ++f)
        ;
    if (f > fmt) {
        len = f - fmt;
        if (len > buflen)
        len = buflen;
        memcpy(buf, fmt, len);
        buf += len;
        buflen -= len;
        fmt = f;
    }
    if (*fmt == 0)
        break;
    c = *++fmt;
    width = 0;
    prec = -1;
    fillch = ' ';
    if (c == '0') {
        fillch = '0';
        c = *++fmt;
    }
    if (c == '*') {
        width = va_arg(args, int);
        c = *++fmt;
    } else {
        while (lwip_isdigit(c)) {
        width = width * 10 + c - '0';
        c = *++fmt;
        }
    }
    if (c == '.') {
        c = *++fmt;
        if (c == '*') {
        prec = va_arg(args, int);
        c = *++fmt;
        } else {
        prec = 0;
        while (lwip_isdigit(c)) {
            prec = prec * 10 + c - '0';
            c = *++fmt;
        }
        }
    }
    str = 0;
    base = 0;
    neg = 0;
    ++fmt;
    switch (c) {
    case 'l':
        c = *fmt++;
        switch (c) {
        case 'd':
        val = va_arg(args, long);
        if ((long)val < 0) {
            neg = 1;
            val = (unsigned long)-(long)val;
        }
        base = 10;
        break;
        case 'u':
        val = va_arg(args, unsigned long);
        base = 10;
        break;
        default:
        OUTCHAR('%');
        OUTCHAR('l');
        --fmt;        /* so %lz outputs %lz etc. */
        continue;
        }
        break;
    case 'd':
        i = va_arg(args, int);
        if (i < 0) {
        neg = 1;
        val = -i;
        } else
        val = i;
        base = 10;
        break;
    case 'u':
        val = va_arg(args, unsigned int);
        base = 10;
        break;
    case 'o':
        val = va_arg(args, unsigned int);
        base = 8;
        break;
    case 'x':
    case 'X':
        val = va_arg(args, unsigned int);
        base = 16;
        break;
    case 'p':
        val = (unsigned long) va_arg(args, void *);
        base = 16;
        neg = 2;
        break;
    case 's':
        str = va_arg(args, char *);
        break;
    case 'c':
        num[0] = va_arg(args, int);
        num[1] = 0;
        str = num;
        break;
#if 0 /* do we always have strerror() in embedded ? */
    case 'm':
        str = strerror(errno);
        break;
#endif /* do we always have strerror() in embedded ? */
    case 'I':
        ip = va_arg(args, uint32_t);
        ip = ntohl(ip);
        ppp_slprintf(num, sizeof(num), "%d.%d.%d.%d", (ip >> 24) & 0xff,
             (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
        str = num;
        break;
    case 't':
        time(&t);
        str = ctime(&t);
        str += 4;        /* chop off the day name */
        str[15] = 0;    /* chop off year and newline */
        break;
    case 'v':        /* "visible" string */
    case 'q':        /* quoted string */
        quoted = c == 'q';
        p = va_arg(args, unsigned char *);
        if (p == NULL)
        p = (const unsigned char *)"<NULL>";
        if (fillch == '0' && prec >= 0) {
        n = prec;
        } else {
        n = (int)strlen((const char *)p);
        if (prec >= 0 && n > prec)
            n = prec;
        }
        while (n > 0 && buflen > 0) {
        c = *p++;
        --n;
        if (!quoted && c >= 0x80) {
            OUTCHAR('M');
            OUTCHAR('-');
            c -= 0x80;
        }
        if (quoted && (c == '"' || c == '\\'))
            OUTCHAR('\\');
        if (c < 0x20 || (0x7f <= c && c < 0xa0)) {
            if (quoted) {
            OUTCHAR('\\');
            switch (c) {
            case '\t':    OUTCHAR('t');    break;
            case '\n':    OUTCHAR('n');    break;
            case '\b':    OUTCHAR('b');    break;
            case '\f':    OUTCHAR('f');    break;
            default:
                OUTCHAR('x');
                OUTCHAR(hexchars[c >> 4]);
                OUTCHAR(hexchars[c & 0xf]);
            }
            } else {
            if (c == '\t')
                OUTCHAR(c);
            else {
                OUTCHAR('^');
                OUTCHAR(c ^ 0x40);
            }
            }
        } else
            OUTCHAR(c);
        }
        continue;
#if PRINTPKT_SUPPORT
    case 'P':        /* print PPP packet */
        bufinfo.ptr = buf;
        bufinfo.len = buflen + 1;
        p = va_arg(args, unsigned char *);
        n = va_arg(args, int);
        ppp_format_packet(p, n, ppp_vslp_printer, &bufinfo);
        buf = bufinfo.ptr;
        buflen = bufinfo.len - 1;
        continue;
#endif /* PRINTPKT_SUPPORT */
    case 'B':
        p = va_arg(args, unsigned char *);
        for (n = prec; n > 0; --n) {
        c = *p++;
        if (fillch == ' ')
            OUTCHAR(' ');
        OUTCHAR(hexchars[(c >> 4) & 0xf]);
        OUTCHAR(hexchars[c & 0xf]);
        }
        continue;
    default:
        *buf++ = '%';
        if (c != '%')
        --fmt;        /* so %z outputs %z etc. */
        --buflen;
        continue;
    }
    if (base != 0) {
        str = num + sizeof(num);
        *--str = 0;
        while (str > num + neg) {
        *--str = hexchars[val % base];
        val = val / base;
        if (--prec <= 0 && val == 0)
            break;
        }
        switch (neg) {
        case 1:
        *--str = '-';
        break;
        case 2:
        *--str = 'x';
        *--str = '0';
        break;
        default:
        break;
        }
        len = num + sizeof(num) - 1 - str;
    } else {
        len = (int)strlen(str);
        if (prec >= 0 && len > prec)
        len = prec;
    }
    if (width > 0) {
        if (width > buflen)
        width = buflen;
        if ((n = width - len) > 0) {
        buflen -= n;
        for (; n > 0; --n)
            *buf++ = fillch;
        }
    }
    if (len > buflen)
        len = buflen;
    memcpy(buf, str, len);
    buf += len;
    buflen -= len;
    }
    *buf = 0;
    return (int)(buf - buf0);
}


int crypto_sha256(const byte_t *data, size_t size, data256_t hash) {
    if (!SHA256(data, size, hash)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

int crypto_sha1(const byte_t *data, size_t size, uint8_t hash[SHA_DIGEST_LENGTH]) {
    if (!SHA1(data, size, hash)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

