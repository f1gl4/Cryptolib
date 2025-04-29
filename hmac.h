#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <cstring>
#include <vector>


/**
 * \brief Calculate HMAC(MD5) from message using key
 * \param key Vector of bytes
 * \param msg Pointer to message array
 * \param msgLen Length of message
 * \return MD5 hash (16 bytes vector)
 */
std::vector<uint8_t> hmac_md5(const std::vector<uint8_t>& key, const uint8_t* msg, size_t msgLen);