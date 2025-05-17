#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <cstring>
#include <iomanip>

/**
 * \brief Structure, stores state of SHA1
 */
struct SHA1Context
{
    // A, B, C, D, E
    uint32_t h[5];

    // Counter of processed bits
    uint64_t bitCount;

    // Buffer for data block
    uint8_t buffer[64];
};

// Initialization
void SHA1_Init(SHA1Context& ctx);

// Add data to the context
void SHA1_Update(SHA1Context& ctx, const uint8_t* data, size_t len);

// Complete the hash calculation and extract the digest
void SHA1_Final(SHA1Context& ctx, uint8_t digest[20]);

/**
 * \brief calculate SHA1
 * \param data Pointer to data
 * \param size Data size (in bytes)
 * \return Vector of 20 bytes (hash)
 */
std::vector<uint8_t> SHA1(const uint8_t* data, size_t size);

/**
 * \brief Convert a 20-byte SHA1 digest to a hex format string
 */
std::string sha1_to_hex(const uint8_t digest[20]);