#include <iostream>

#include "md5.h"
#include "keygen.h"
#include "hmac.h"
#include "rsa.h"
#include "sha1.h"

static void print_usage() {
    std::cout << "Usage:\n"
              << "crypto md5 <string>\n"
              << "crypto sha1 <string>\n"
              << "crypto keygen <length>\n"
              << "crypto hmac-md5 <key> <string>\n"
              << "crypto rsa gen <p> <q>\n"
              << "crypto rsa encrypt <p> <q> <string>\n"
              << "crypto rsa decrypt <p> <q> <string>\n";
}

int main(int argc, char* argv[]) {

    /*auto key128 = generateKey(16);
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
    }*/

    /*RSA rsa(11, 13);
    auto pub = rsa.publicKey();
    auto prv = rsa.privateKey();
    std::cout << "e = " << pub.second << "; d = " << prv.second << std::endl;

    std::string msg = "hello";
    auto enc = rsa.encrypt(msg);
    auto dec = rsa.decrypt(enc);

    std::cout << "ciphertext: ";
    for (auto v : enc) std::cout << v << ' ';
    std::cout << "\nplaintext: " << dec << '\n';*/

    /*const std::string msg = "hello";
    auto d = SHA1((const uint8_t*)msg.data(), msg.size());
    std::cout << sha1_to_hex(d.data()) << '\n';*/



    return 0;
}
