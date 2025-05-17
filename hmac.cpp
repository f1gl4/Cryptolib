#include "hmac.h"
#include "md5.h"
#include "sha1.h"

std::vector<uint8_t> hmac_md5(const std::vector<uint8_t>& key, const uint8_t* msg, size_t msgLen)
{
    std::vector<uint8_t> k = key;
    if (k.size() > 64)
    {
        k = MD5(k.data(), k.size());
    }

    k.resize(64, 0x00);

    std::vector<uint8_t> ipad(64), opad(64);
    for (size_t i = 0; i < 64; i++)
    {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }

    // innerHash = MD5(ipad || msg)
    MD5Context ctx;
    MD5_Init(ctx);
    MD5_Update(ctx, ipad.data(), ipad.size());
    MD5_Update(ctx, msg, msgLen);

    uint8_t innerHash[64];
    MD5_Final(ctx, innerHash);

    // outerHash = MD5(opad || innerHash)
    MD5_Init(ctx);
    MD5_Update(ctx, opad.data(), opad.size());
    MD5_Update(ctx, innerHash, 16);

    std::vector<uint8_t> hmac(16);
    MD5_Final(ctx, hmac.data());
    return hmac;

}

std::vector<uint8_t> hmac_sha1(const std::vector<uint8_t>& key, const uint8_t* msg, size_t msgLen)
{
    std::vector<uint8_t> k = key;
    if (k.size() > 64)
    {
        k = SHA1(k.data(), k.size());
    }

    k.resize(64, 0x00);

    std::vector<uint8_t> ipad(64), opad(64);
    for (size_t i = 0; i < 64; i++)
    {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }

    // innerHash = SHA1(ipad || msg)
    SHA1Context ctx;
    SHA1_Init(ctx);
    SHA1_Update(ctx, ipad.data(), ipad.size());
    SHA1_Update(ctx, msg, msgLen);

    uint8_t innerHash[20];
    SHA1_Final(ctx, innerHash);

    // outerHash = MD5(opad || innerHash)
    SHA1_Init(ctx);
    SHA1_Update(ctx, opad.data(), opad.size());
    SHA1_Update(ctx, innerHash, sizeof(innerHash));

    std::vector<uint8_t> hmac(20);
    SHA1_Final(ctx, hmac.data());
    return hmac;

}