// UTF-8 <-> UTF-16 for the SoftEther core's iconv calls (see iconv.h). Any name other than UTF-16LE/BE counts as UTF-8,
// the character set Android uses. Errors follow POSIX: E2BIG when the output is full, EILSEQ for a bad sequence, EINVAL
// for an incomplete one at the end of the input.

#include "iconv.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>

typedef struct {
  int to_utf16;     // 1: UTF-8 -> UTF-16, 0: UTF-16 -> UTF-8
  int big_endian;   // of the UTF-16 side
} converter_t;

static int utf16_kind(const char *name) {
  if (strcasecmp(name, "UTF-16LE") == 0) return 1;
  if (strcasecmp(name, "UTF-16BE") == 0) return 2;
  return 0;
}

iconv_t iconv_open(const char *to, const char *from) {
  int to_kind = utf16_kind(to), from_kind = utf16_kind(from);
  if ((to_kind == 0) == (from_kind == 0)) {
    errno = EINVAL;
    return (iconv_t)-1;
  }
  converter_t *converter = malloc(sizeof(*converter));
  if (converter == NULL) {
    errno = ENOMEM;
    return (iconv_t)-1;
  }
  converter->to_utf16 = to_kind != 0;
  converter->big_endian = (to_kind ? to_kind : from_kind) == 2;
  return converter;
}

int iconv_close(iconv_t cd) {
  free(cd);
  return 0;
}

static uint32_t read16(const unsigned char *p, int big_endian) {
  return big_endian ? (uint32_t)(p[0] << 8 | p[1]) : (uint32_t)(p[1] << 8 | p[0]);
}

static void write16(unsigned char *p, uint32_t unit, int big_endian) {
  p[big_endian ? 0 : 1] = (unsigned char)(unit >> 8);
  p[big_endian ? 1 : 0] = (unsigned char)unit;
}

size_t iconv(iconv_t cd, char **in, size_t *in_left, char **out, size_t *out_left) {
  converter_t *converter = cd;
  if (converter == NULL || converter == (void *)-1) {
    errno = EBADF;
    return (size_t)-1;
  }
  if (in == NULL || *in == NULL) {
    return 0;   // no shift state to reset
  }
  const unsigned char *source = (const unsigned char *)*in;
  unsigned char *target = (unsigned char *)*out;
  size_t source_left = *in_left, target_left = *out_left;
  size_t result = 0;
  while (source_left > 0) {
    uint32_t code;
    size_t used;
    if (converter->to_utf16) {
      unsigned char lead = source[0];
      size_t length = lead < 0x80 ? 1 : (lead >> 5) == 0x6 ? 2 : (lead >> 4) == 0xe ? 3 : (lead >> 3) == 0x1e ? 4 : 0;
      if (length == 0) { errno = EILSEQ; result = (size_t)-1; break; }
      if (source_left < length) { errno = EINVAL; result = (size_t)-1; break; }
      code = length == 1 ? lead : lead & (0xff >> (length + 1));
      for (size_t i = 1; i < length; i++) {
        if ((source[i] & 0xc0) != 0x80) { length = 0; break; }
        code = code << 6 | (source[i] & 0x3f);
      }
      if (length == 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) { errno = EILSEQ; result = (size_t)-1; break; }
      used = length;
      size_t needed = code >= 0x10000 ? 4 : 2;
      if (target_left < needed) { errno = E2BIG; result = (size_t)-1; break; }
      if (code >= 0x10000) {
        code -= 0x10000;
        write16(target, 0xd800 | (code >> 10), converter->big_endian);
        write16(target + 2, 0xdc00 | (code & 0x3ff), converter->big_endian);
      } else {
        write16(target, code, converter->big_endian);
      }
      target += needed;
      target_left -= needed;
    } else {
      if (source_left < 2) { errno = EINVAL; result = (size_t)-1; break; }
      code = read16(source, converter->big_endian);
      used = 2;
      if (code >= 0xd800 && code <= 0xdbff) {
        if (source_left < 4) { errno = EINVAL; result = (size_t)-1; break; }
        uint32_t low = read16(source + 2, converter->big_endian);
        if (low < 0xdc00 || low > 0xdfff) { errno = EILSEQ; result = (size_t)-1; break; }
        code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
        used = 4;
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        errno = EILSEQ; result = (size_t)-1; break;
      }
      size_t needed = code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
      if (target_left < needed) { errno = E2BIG; result = (size_t)-1; break; }
      if (needed == 1) {
        target[0] = (unsigned char)code;
      } else {
        for (size_t i = needed - 1; i > 0; i--) {
          target[i] = (unsigned char)(0x80 | (code & 0x3f));
          code >>= 6;
        }
        target[0] = (unsigned char)((0xff00 >> needed) | code);
      }
      target += needed;
      target_left -= needed;
    }
    source += used;
    source_left -= used;
  }
  *in = (char *)source;
  *in_left = source_left;
  *out = (char *)target;
  *out_left = target_left;
  return result;
}
