#pragma once

#include "md5.h"


// Define LITTLE_ENDIAN / BIG_ENDIAN
#define LITTLE_ENDIAN 0
#define BIG_ENDIAN    1

static bool getEndianness() 
{
    uint32_t x = 1;
    return (*reinterpret_cast<uint8_t*>(&x) == 1) ? LITTLE_ENDIAN : BIG_ENDIAN;
}

// Table T
static const uint32_t T[65] = 
{
    0,
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,

    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,

    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,

    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

// Rounds
static inline uint32_t rotate_left(uint32_t x, uint32_t s) 
{
    return (x << s) | (x >> (32 - s));
}

static uint32_t F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
static uint32_t G(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (~z & y); }
static uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static uint32_t I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (~z | x); }

static void round_func(uint32_t &w, uint32_t x, uint32_t y, uint32_t z,
                              uint32_t M, uint32_t s, uint32_t i,
                              uint32_t(*func)(uint32_t, uint32_t, uint32_t))
{
    w += func(x, y, z) + M + T[i];
    w = rotate_left(w, s);
    w += x;
}


void MD5_Init(MD5Context &ctx) 
{

    ctx.a = 0x67452301;
    ctx.b = 0xEFCDAB89;
    ctx.c = 0x98BADCFE;
    ctx.d = 0x10325476;

    ctx.bitCount = 0;
    std::memset(ctx.buffer, 0, 64);
}


static void process_block(MD5Context &ctx, const uint8_t block[64]) 
{
    // read 64 bytes as 16 words of 4 bytes each
    uint32_t M[16];
    for (int i = 0; i < 16; i++) {
        M[i] = (uint32_t)block[i*4] |
               ((uint32_t)block[i*4 + 1] << 8) |
               ((uint32_t)block[i*4 + 2] << 16) |
               ((uint32_t)block[i*4 + 3] << 24);
    }

    uint32_t A = ctx.a;
    uint32_t B = ctx.b;
    uint32_t C = ctx.c;
    uint32_t D = ctx.d;

    //  1. 16 rounds F()
    round_func(A, B, C, D, M[0],  7,  1,  F);
    round_func(D, A, B, C, M[1],  12, 2,  F);
    round_func(C, D, A, B, M[2],  17, 3,  F);
    round_func(B, C, D, A, M[3],  22, 4,  F);

    round_func(A, B, C, D, M[4],  7,  5,  F);
    round_func(D, A, B, C, M[5],  12, 6,  F);
    round_func(C, D, A, B, M[6],  17, 7,  F);
    round_func(B, C, D, A, M[7],  22, 8,  F);

    round_func(A, B, C, D, M[8],  7,  9,  F);
    round_func(D, A, B, C, M[9],  12, 10, F);
    round_func(C, D, A, B, M[10], 17, 11, F);
    round_func(B, C, D, A, M[11], 22, 12, F);

    round_func(A, B, C, D, M[12], 7,  13, F);
    round_func(D, A, B, C, M[13], 12, 14, F);
    round_func(C, D, A, B, M[14], 17, 15, F);
    round_func(B, C, D, A, M[15], 22, 16, F);

    //  2. 16 rounds G()
    round_func(A, B, C, D, M[1],  5,  17, G);
    round_func(D, A, B, C, M[6],  9,  18, G);
    round_func(C, D, A, B, M[11], 14, 19, G);
    round_func(B, C, D, A, M[0],  20, 20, G);

    round_func(A, B, C, D, M[5],  5,  21, G);
    round_func(D, A, B, C, M[10], 9,  22, G);
    round_func(C, D, A, B, M[15], 14, 23, G);
    round_func(B, C, D, A, M[4],  20, 24, G);

    round_func(A, B, C, D, M[9],  5,  25, G);
    round_func(D, A, B, C, M[14], 9,  26, G);
    round_func(C, D, A, B, M[3],  14, 27, G);
    round_func(B, C, D, A, M[8],  20, 28, G);

    round_func(A, B, C, D, M[13], 5,  29, G);
    round_func(D, A, B, C, M[2],  9,  30, G);
    round_func(C, D, A, B, M[7],  14, 31, G);
    round_func(B, C, D, A, M[12], 20, 32, G);

    //  3. 16 rounds H()
    round_func(A, B, C, D, M[5],  4,  33, H);
    round_func(D, A, B, C, M[8],  11, 34, H);
    round_func(C, D, A, B, M[11], 16, 35, H);
    round_func(B, C, D, A, M[14], 23, 36, H);

    round_func(A, B, C, D, M[1],  4,  37, H);
    round_func(D, A, B, C, M[4],  11, 38, H);
    round_func(C, D, A, B, M[7],  16, 39, H);
    round_func(B, C, D, A, M[10], 23, 40, H);

    round_func(A, B, C, D, M[13], 4,  41, H);
    round_func(D, A, B, C, M[0],  11, 42, H);
    round_func(C, D, A, B, M[3],  16, 43, H);
    round_func(B, C, D, A, M[6],  23, 44, H);

    round_func(A, B, C, D, M[9],  4,  45, H);
    round_func(D, A, B, C, M[12], 11, 46, H);
    round_func(C, D, A, B, M[15], 16, 47, H);
    round_func(B, C, D, A, M[2],  23, 48, H);

    //  4. 16 rounds I()
    round_func(A, B, C, D, M[0],  6,  49, I);
    round_func(D, A, B, C, M[7],  10, 50, I);
    round_func(C, D, A, B, M[14], 15, 51, I);
    round_func(B, C, D, A, M[5],  21, 52, I);

    round_func(A, B, C, D, M[12], 6,  53, I);
    round_func(D, A, B, C, M[3],  10, 54, I);
    round_func(C, D, A, B, M[10], 15, 55, I);
    round_func(B, C, D, A, M[1],  21, 56, I);

    round_func(A, B, C, D, M[8],  6,  57, I);
    round_func(D, A, B, C, M[15], 10, 58, I);
    round_func(C, D, A, B, M[6],  15, 59, I);
    round_func(B, C, D, A, M[13], 21, 60, I);

    round_func(A, B, C, D, M[4],  6,  61, I);
    round_func(D, A, B, C, M[11], 10, 62, I);
    round_func(C, D, A, B, M[2],  15, 63, I);
    round_func(B, C, D, A, M[9],  21, 64, I);


    ctx.a += A;
    ctx.b += B;
    ctx.c += C;
    ctx.d += D;
}


void MD5_Update(MD5Context &ctx, const uint8_t* data, size_t len) 
{

    ctx.bitCount += (uint64_t)len * 8;

    size_t bufferBytes = (ctx.bitCount/8) % 64; 
    uint64_t oldBitCount = ctx.bitCount - (uint64_t)len * 8;
    size_t offset = (oldBitCount / 8) % 64;

    size_t i = 0;
    while (i < len) {
        size_t spaceInBuffer = 64 - offset;
        size_t copyBytes = (len - i < spaceInBuffer) ? (len - i) : spaceInBuffer;

        std::memcpy(ctx.buffer + offset, data + i, copyBytes);
        i += copyBytes;
        offset += copyBytes;

        // if buffer is full
        if (offset == 64) {
            process_block(ctx, ctx.buffer);
            offset = 0;
        }
    }
}


void MD5_Final(MD5Context &ctx, uint8_t output[16]) 
{

    size_t offset = (ctx.bitCount / 8) % 64;

    ctx.buffer[offset++] = 0x80;

    if (offset > 56) {
        std::memset(ctx.buffer + offset, 0, 64 - offset);
        process_block(ctx, ctx.buffer);
        std::memset(ctx.buffer, 0, 56);
    } else {
        std::memset(ctx.buffer + offset, 0, 56 - offset);
    }

    uint64_t bits = ctx.bitCount;
    uint8_t* lengthPtr = ctx.buffer + 56;
    std::memcpy(lengthPtr, &bits, 8);

    if (getEndianness() == BIG_ENDIAN) {
        std::swap(lengthPtr[0], lengthPtr[7]);
        std::swap(lengthPtr[1], lengthPtr[6]);
        std::swap(lengthPtr[2], lengthPtr[5]);
        std::swap(lengthPtr[3], lengthPtr[4]);
    }

    process_block(ctx, ctx.buffer);

    std::memcpy(output + 0, &ctx.a, 4);
    std::memcpy(output + 4, &ctx.b, 4);
    std::memcpy(output + 8, &ctx.c, 4);
    std::memcpy(output + 12, &ctx.d, 4);
}


std::vector<uint8_t> MD5(const uint8_t* data, size_t size) 
{
    MD5Context ctx;
    MD5_Init(ctx);
    MD5_Update(ctx, data, size);

    std::vector<uint8_t> digest(16);
    MD5_Final(ctx, digest.data());
    return digest;
}


std::string md5hash_to_string(const uint8_t hash[16]) 
{
    static const char* hex = "0123456789abcdef";
    std::string ret;
    ret.reserve(32);

    for (int i = 0; i < 16; ++i) {
        ret.push_back(hex[ (hash[i] >> 4) & 0x0F ]);
        ret.push_back(hex[ hash[i] & 0x0F ]);
    }
    return ret;
}
