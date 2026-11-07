// Host check of iconv_shim.c (not part of the app): clang -I. -o /tmp/iconv_shim_test iconv_shim_test.c iconv_shim.c && /tmp/iconv_shim_test
#include "iconv.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
int main(void) {
  const char *utf8 = "A\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80";   // A é € 😀
  unsigned char wide[32]; char back[32];
  iconv_t to = iconv_open("UTF-16LE", "utf-8"), from = iconv_open("EUCJP", "UTF-16LE");
  char *in = (char *)utf8, *out = (char *)wide; size_t inl = strlen(utf8), outl = sizeof(wide);
  assert(iconv(to, &in, &inl, &out, &outl) == 0 && inl == 0);
  size_t wlen = sizeof(wide) - outl;
  assert(wlen == 10 && wide[0] == 'A' && wide[2] == 0xe9 && wide[4] == 0xac && wide[5] == 0x20 && wide[6] == 0x3d && wide[7] == 0xd8);
  in = (char *)wide; inl = wlen; out = back; outl = sizeof(back);
  assert(iconv(from, &in, &inl, &out, &outl) == 0 && inl == 0);
  assert(sizeof(back) - outl == strlen(utf8) && memcmp(back, utf8, strlen(utf8)) == 0);
  in = (char *)utf8; inl = strlen(utf8); out = (char *)wide; outl = 3;   // E2BIG keeps whole characters only
  assert(iconv(to, &in, &inl, &out, &outl) == (size_t)-1 && errno == E2BIG && outl == 1 && inl == strlen(utf8) - 1);
  char bad[] = "\xff"; in = bad; inl = 1; out = (char *)wide; outl = sizeof(wide);
  assert(iconv(to, &in, &inl, &out, &outl) == (size_t)-1 && errno == EILSEQ);
  assert(iconv_open("UTF-8", "EUCJP") == (iconv_t)-1);
  iconv_close(to); iconv_close(from);
  puts("iconv shim ok");
  return 0;
}
