#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm> 


/**
 * \brief Structure, stores state of MD5
 */
struct MD5Context {

    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;

    // Counter of processed bits 
    uint64_t bitCount;

    // Buffer for data if it is not 64 bytes long
    unsigned char buffer[64];
};

// Initialization
void MD5_Init(MD5Context &ctx);

// Add another piece of data to the context, call process_block if the buffer is full
void MD5_Update(MD5Context &ctx, const uint8_t* data, size_t len);

// Complete the hash calculation and return a 16-byte result
void MD5_Final(MD5Context &ctx, uint8_t output[16]);

/**
 * \brief calculate MD5
 * \param data Pointer to data
 * \param size Data size (in bytes)
 * \return Vector of 16 bytes (hash)
 */
std::vector<uint8_t> MD5(const uint8_t* data, size_t size);

/**
 * \brief Convert a 16-byte MD5 hash to a hex format string
 */
std::string md5hash_to_string(const uint8_t hash[16]);

