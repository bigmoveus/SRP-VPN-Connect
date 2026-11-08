/*
 * SRP VPN Connect: a password given in UTF-8 as the Unicode that MS-CHAP hashes (RFC 2759's NtPasswordHash takes the
 * password as UTF-16LE). Windows and FreeRADIUS turn the password's characters into UTF-16, so a byte-per-character
 * copy matched them only for ASCII; SoftEther's and pppd's MS-CHAP still widen each byte, so a password with
 * characters outside ASCII matches one kind of server or the other, never both. The SSTP client hashes as UTF-16 first
 * and, when a server refuses such a password, tries once more byte by byte (srp_mschap_bytewise_password).
 * Used by chap_ms.c (MS-CHAP and EAP-MSCHAPv2) and by the SSTP crypto binding in sstp-chap.c.
 */
#ifndef SRP_UTF16LE_H
#define SRP_UTF16LE_H

#include <stdint.h>

/* 1: hash the password one byte per character, as SoftEther and pppd do; defined in chap_ms.c, set by the SSTP client */
extern int srp_mschap_bytewise_password;

/* UTF-8 to UTF-16LE: writes at most outlen bytes, whole characters only, and returns how many it wrote. A byte that does
 * not start valid UTF-8 counts as one character (Latin-1), as it did before. Java's modified UTF-8 (JNI) writes a
 * character past U+FFFF as two 3-byte surrogates; they come out as the same UTF-16 pair. */
static inline int srp_utf8_to_utf16le(const char *in, int inlen, unsigned char *out, int outlen) {
    const unsigned char *s = (const unsigned char *)in;
    int i = 0, o = 0;
    while (i < inlen) {
        uint32_t cp = s[i];
        int extra = cp < 0x80 ? 0 : (cp & 0xE0) == 0xC0 ? 1 : (cp & 0xF0) == 0xE0 ? 2 : (cp & 0xF8) == 0xF0 ? 3 : -1;
        if (extra > 0) {
            uint32_t v = cp & (0x3Fu >> extra);
            int k;
            for (k = 1; k <= extra && i + k < inlen && (s[i + k] & 0xC0) == 0x80; k++)
                v = (v << 6) | (s[i + k] & 0x3F);
            /* a cut sequence, an overlong form or a value past U+10FFFF is not UTF-8 */
            if (k <= extra || v < (extra == 1 ? 0x80u : extra == 2 ? 0x800u : 0x10000u) || v > 0x10FFFF)
                extra = 0;
            else
                cp = v;
        } else {
            extra = 0;
        }
        if (cp >= 0x10000) {
            uint32_t u = cp - 0x10000, hi = 0xD800 | (u >> 10), lo = 0xDC00 | (u & 0x3FF);
            if (o + 4 > outlen) break;
            out[o++] = (unsigned char)hi; out[o++] = (unsigned char)(hi >> 8);
            out[o++] = (unsigned char)lo; out[o++] = (unsigned char)(lo >> 8);
        } else {
            if (o + 2 > outlen) break;
            out[o++] = (unsigned char)cp; out[o++] = (unsigned char)(cp >> 8);
        }
        i += extra + 1;
    }
    return o;
}

/* The password as MS-CHAP hashes it: its characters as UTF-16LE, or each byte widened when bytewise is set */
static inline int srp_mschap_password_unicode(const char *in, int inlen, unsigned char *out, int outlen, int bytewise) {
    int i, o = 0;
    if (!bytewise)
        return srp_utf8_to_utf16le(in, inlen, out, outlen);
    for (i = 0; i < inlen && o + 2 <= outlen; i++) {
        out[o++] = (unsigned char)in[i];
        out[o++] = 0;
    }
    return o;
}

#endif /* SRP_UTF16LE_H */
