#pragma once

#include "sha1.h"


// macros

#define ROTL(x,n) (((x) << (n)) | ((x) >> (32 - (n)))) // rotate-left
#define F0(b,c,d) (((b) & (c)) | (~(b) & (d)))
#define F1(b,c,d) ((b) ^ (c) ^ (d))
#define F2(b,c,d) (((b) & (c)) | ((b) & (d)) | ((c) & (d)))
#define F3(b,c,d) ((b) ^ (c) ^ (d))

// read/write 32-bit word in big-endian

static inline uint32_t be32(const uint8_t* p)
{
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static inline void put_be32(uint8_t* p, uint32_t v)
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

// 512-bit round

static void sha1_block(SHA1Context& ctx, const uint8_t block[64])
{
    uint32_t w[80];

    for (int i = 0; i < 16; ++i)
    {
        w[i] = be32(block + 4 * i);
    }
    for (int i = 16; i < 80; ++i)
    {
        w[i] = ROTL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }


    uint32_t a = ctx.h[0];
    uint32_t b = ctx.h[1];
    uint32_t c = ctx.h[2];
    uint32_t d = ctx.h[3];
    uint32_t e = ctx.h[4];

    for (int i = 0; i < 80; ++i)
    {
        uint32_t f, k;
        if (i < 20) { f = F0(b,c,d); k = 0x5A827999; }
        else if (i < 40) { f = F1(b,c,d); k = 0x6ED9EBA1; }
        else if (i < 60) { f = F2(b,c,d); k = 0x8F1BBCDC; }
        else { f = F3(b,c,d); k = 0xCA62C1D6; }
        
        uint32_t temp = ROTL(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = ROTL(b, 30);
        b = a;
        a = temp;
    }

    ctx.h[0] += a; ctx.h[1] += b; ctx.h[2] += c; ctx.h[3] += d; ctx.h[4] += e;
}

void SHA1_Init(SHA1Context& ctx)
{
    ctx.h[0] = 0x67452301;
    ctx.h[1] = 0xEFCDAB89;
    ctx.h[2] = 0x98BADCFE;
    ctx.h[3] = 0x10325476;
    ctx.h[4] = 0xC3D2E1F0;
    ctx.bitCount = 0;
    std::memset(ctx.buffer, 0, 64);
}

void SHA1_Update(SHA1Context& ctx, const uint8_t* data, size_t size)
{
    size_t idx = (ctx.bitCount / 8) % 64;
    ctx.bitCount += (uint64_t)size * 8;

    size_t i = 0;
    if (idx)
    {
        size_t toCopy = 64 - idx;
        if (toCopy > size)
        {
            toCopy = size;
        }

        std::memcpy(ctx.buffer + idx, data, toCopy);
        idx += toCopy;
        i += toCopy;

        if (idx == 64)
        {
            sha1_block(ctx, ctx.buffer);
            idx = 0;
        }
    }

    for ( ; i + 63 < size; i += 64)
    {
        sha1_block(ctx, data + i);  // full block
    }
    if (i < size)
    {
        std::memcpy(ctx.buffer, data + i, size - i); // remains
    }
}

void SHA1_Final(SHA1Context& ctx, uint8_t digest[20])
{
    size_t idx = (ctx.bitCount / 8) % 64;
    ctx.buffer[idx++] = 0x80;
    if (idx > 56)
    {
        std::memset(ctx.buffer + idx, 0, 64 - idx);
        sha1_block(ctx, ctx.buffer);
        idx = 0;
    }

    std::memset(ctx.buffer + idx, 0, 56 - idx);
    uint64_t bitsBE = __builtin_bswap64(ctx.bitCount);
    std::memcpy(ctx.buffer + 56, &bitsBE, 8);
    sha1_block(ctx, ctx.buffer);

    for (int i = 0; i < 5; ++i)
    {
        put_be32(digest + 4 * i, ctx.h[i]);
    }
}

std::vector<uint8_t> SHA1(const uint8_t* data, size_t size)
{
    SHA1Context ctx;
    SHA1_Init(ctx);
    SHA1_Update(ctx, data, size);
    std::vector<uint8_t> out(20);
    SHA1_Final(ctx, out.data());
    return out;
}

std::string sha1_to_hex(const uint8_t digest[20])
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 20; ++i)
    {
        oss << std::setw(2) << (int)digest[i];
    }
    return oss.str();
}