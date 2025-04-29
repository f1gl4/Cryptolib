#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>
#include <random>

/**
 * \brief Generate random set of bytes - key
 * \param size Count of key's bytes (16 for AES-128, 32 for AES-256)
 * \return Vector bytes
 */
std::vector<uint8_t> generateKey(size_t size);

void print_hex_key(const std::vector<uint8_t>& key);