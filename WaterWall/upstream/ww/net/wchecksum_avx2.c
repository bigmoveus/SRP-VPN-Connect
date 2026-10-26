#include "wlibc.h"

/*
 * AVX2-optimized checksum backend compatible with checksumDefault semantics.
 */

uint16_t checksumAVX2(const uint8_t *, uint16_t, uint32_t);

/**
 * @brief Compute checksum using AVX2 vectorized accumulation.
 *
 * @param addr Input bytes.
 * @param len Number of bytes.
 * @param csum Initial running sum seed.
 * @return uint16_t One's-complement checksum in network byte order.
 */
uint16_t checksumAVX2(const uint8_t *addr, uint16_t len, uint32_t csum)
{
    uint_fast64_t  acc;
    const uint8_t *buf       = (const uint8_t *) addr;
    uint16_t       remainder = 0; /* fixed size for endian swap */
    uint_fast16_t  count2;
    uint_fast16_t  count32;
    bool           is_odd = ((uintptr_t) buf & 1);

    /* Keep seed convention identical to checksumDefault. */
    if (is_odd)
    {
        /* Odd-aligned path swaps at the end; keep seed as-is. */
        acc = csum;
    }
    else
    {
        /* Even-aligned path operates on little-endian words. */
        csum = (csum & 0xFFFFU) + (csum >> 16);
        csum = (csum & 0xFFFFU) + (csum >> 16);
        acc  = lwip_htons((uint16_t) csum);
    }

    /* align first byte */
    if (UNLIKELY(is_odd && len > 0))
    {
        ((uint8_t *) &remainder)[1] = *buf++;
        len--;
    }
    /* 256-bit, 32-byte stride */
    count32            = len >> 5;
    const __m256i zero = _mm256_setzero_si256();
    __m256i       sum  = zero;
    while (count32--)
    {
        __m256i tmp = _mm256_lddqu_si256((const __m256i *) buf); // load 256-bit blob

        __m256i lo = _mm256_unpacklo_epi16(tmp, zero);
        __m256i hi = _mm256_unpackhi_epi16(tmp, zero);

        sum = _mm256_add_epi32(sum, lo);
        sum = _mm256_add_epi32(sum, hi);
        buf += 32;
    }

    // add all 32-bit components together
    sum = _mm256_add_epi32(sum, _mm256_srli_si256(sum, 8));
    sum = _mm256_add_epi32(sum, _mm256_srli_si256(sum, 4));
#ifndef _MSC_VER
    acc += _mm256_extract_epi32(sum, 0) + _mm256_extract_epi32(sum, 4);
#else
    {
        __m128i __Y1 = _mm256_extractf128_si256(sum, 0 >> 2);
        __m128i __Y2 = _mm256_extractf128_si256(sum, 4 >> 2);
        acc += _mm_extract_epi32(__Y1, 0 % 4) + _mm_extract_epi32(__Y2, 4 % 4);
    }
#endif
    len %= 32;
    /* final 31 bytes */
    count2 = len >> 1;
    while (count2--)
    {
        acc += ((const uint16_t *) buf)[0];
        buf += 2;
    }
    /* trailing odd byte */
    if (len & 1)
    {
        ((uint8_t *) &remainder)[0] = *buf;
    }
    acc += remainder;
    acc = (acc >> 32) + (acc & 0xffffffff);
    acc = (acc >> 16) + (acc & 0xffff);
    acc = (acc >> 16) + (acc & 0xffff);
    acc += (acc >> 16);
    if (UNLIKELY(is_odd))
    {
        acc = ((acc & 0xff) << 8) | ((acc & 0xff00) >> 8);
    }
    return (uint16_t) ~acc;
}
