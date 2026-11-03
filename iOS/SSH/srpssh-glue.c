/*
 * srpssh-glue.c — definitions for the lwIP helper functions whose upstream
 * definitions in def.c are suppressed by the #ifndef guards once the
 * srpssh-prefix.h macros are in place. Callers are renamed to srpssh_* by
 * the prefix header; these provide the matching definitions.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

uint16_t srpssh_lwip_htons(uint16_t x) { return __builtin_bswap16(x); }
uint32_t srpssh_lwip_htonl(uint32_t x) { return __builtin_bswap32(x); }

void srpssh_lwip_itoa(char *result, size_t bufsize, int number) {
    snprintf(result, bufsize, "%d", number);
}

int srpssh_lwip_strnicmp(const char *str1, const char *str2, size_t len) {
    return strncasecmp(str1, str2, len);
}

int srpssh_lwip_stricmp(const char *str1, const char *str2) {
    return strcasecmp(str1, str2);
}

char *srpssh_lwip_strnstr(const char *buffer, const char *token, size_t n) {
    size_t tlen = strlen(token);
    if (tlen == 0) return (char *)buffer;
    for (size_t i = 0; i + tlen <= n && buffer[i]; i++) {
        if (strncmp(buffer + i, token, tlen) == 0)
            return (char *)(buffer + i);
    }
    return NULL;
}

char *srpssh_lwip_strnistr(const char *buffer, const char *token, size_t n) {
    size_t tlen = strlen(token);
    if (tlen == 0) return (char *)buffer;
    for (size_t i = 0; i + tlen <= n && buffer[i]; i++) {
        size_t j;
        for (j = 0; j < tlen; j++) {
            if (tolower((unsigned char)buffer[i + j]) != tolower((unsigned char)token[j]))
                break;
        }
        if (j == tlen)
            return (char *)(buffer + i);
    }
    return NULL;
}

int srpssh_lwip_memcmp_consttime(const void *s1, const void *s2, size_t len) {
    const uint8_t *a = s1, *b = s2;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return diff;
}
