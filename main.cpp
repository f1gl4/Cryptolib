#include <iostream>

#include "md5.h"
#include "keygen.h"
#include "hmac.h"

int main() {

    auto key128 = generateKey(16);
    std::cout << "Random key (16 bytes): ";
    print_hex_key(key128);

    std::string msg = "hello world";
    auto hmac = hmac_md5(key128, (const uint8_t*)msg.data(), msg.size());
    std::cout << "HMAC(MD5) for msg = hello world: " << md5hash_to_string(hmac.data()) << std::endl;

    while (true) {
        std::cout << "Input: ";
        std::string s;
        if (!std::getline(std::cin, s) || s.empty()) {
            break;
        }

        std::vector<uint8_t> hash = MD5((const uint8_t*)s.data(), s.size());
        std::string hexStr = md5hash_to_string(hash.data());

        std::cout << "MD5 hash: " << hexStr << std::endl << std::endl;
    }

    return 0;
}
