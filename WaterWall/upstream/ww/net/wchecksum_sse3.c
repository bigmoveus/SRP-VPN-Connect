#include "wlibc.h"

/*
 * SSE3-optimized checksum backend compatible with checksumDefault semantics.
 */

uint16_t checksumSSE3(const uint8_t *addr, uint16_t len, uint32_t csum);

/**
 * @brief Compute checksum using SSE3 vectorized accumulation.
 *
 * @param addr Input bytes.
 * @param len Number of bytes.
 * @param csum Initial running sum seed.
 * @return uint16_t One's-complement checksum in network byte order.
 */
uint16_t checksumSSE3(const uint8_t *addr, uint16_t len, uint32_t csum)
{
    uint_fast64_t  acc;
    const uint8_t *buf       = (const uint8_t *) addr;
    uint16_t       remainder = 0; /* fixed size for endian swap */
    uint_fast16_t  count2;
    uint_fast16_t  count16;
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
    /* 128-bit, 16-byte stride */
    count16            = len >> 4;
    const __m128i zero = _mm_setzero_si128();
    __m128i       sum  = zero;
    while (count16--)
    {
        __m128i tmp = _mm_lddqu_si128((const __m128i *) buf); // load 128-bit blob

        /* marginal gain with zero constant over _mm_setzero_si128().
         */
        __m128i lo = _mm_unpacklo_epi16(tmp, zero); // interleave 4×16-bit
        __m128i hi = _mm_unpackhi_epi16(tmp, zero);

        sum = _mm_add_epi32(sum, lo); // add 4×32-bit
        sum = _mm_add_epi32(sum, hi);
        buf += 16;
    }

    // add all 32-bit components together
    sum = _mm_add_epi32(sum, _mm_srli_si128(sum, 8)); // shift right 8 bytes
    sum = _mm_add_epi32(sum, _mm_srli_si128(sum, 4));
    acc += _mm_cvtsi128_si32(sum);
    len %= 16;
    /* final 15 bytes */
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
