// iconv.h for the SoftEther core on Android: Bionic has iconv only from API 28 and the app starts at API 26. The core
// only converts between its character set and UTF-16 (Mayaqua/Internat.c), so iconv_shim.c does UTF-8 <-> UTF-16LE/BE.
#ifndef SRP_ICONV_SHIM_H
#define SRP_ICONV_SHIM_H

#include <stddef.h>

typedef void *iconv_t;

iconv_t iconv_open(const char *to, const char *from);
size_t iconv(iconv_t cd, char **in, size_t *in_left, char **out, size_t *out_left);
int iconv_close(iconv_t cd);

#endif
