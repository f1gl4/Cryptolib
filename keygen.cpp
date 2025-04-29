#include "keygen.h"

std::vector<uint8_t> generateKey(std::size_t size)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);

    std::vector<uint8_t> key(size);
    for (size_t i = 0; i < size; i++)
    {
        key[i] = static_cast<uint8_t>(dist(gen));
    }
    return key;
}

void print_hex_key(const std::vector<uint8_t>& key)
{
    auto lambda = [](const std::vector<uint8_t> &key) {
        for (auto b : key) 
        {
            printf("%02x", b);
        }
        printf("\n");
    };

    lambda(key);
}

