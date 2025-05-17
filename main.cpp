#include <iostream>

#include "md5.h"
#include "keygen.h"
#include "hmac.h"
#include "rsa.h"
#include "sha1.h"

static void print_usage() {
    std::cout << "Usage:\n"
              << "./Cryptolib md5 <string>\n"
              << "./Cryptolib sha1 <string>\n"
              << "./Cryptolib keygen <length>\n"
              << "./Cryptolib hmac-md5 <key> <string>\n"
              << "./Cryptolib hmac-sha1 <key> <string>\n"
              << "./Cryptolib rsa gen <p> <q>\n"
              << "./Cryptolib rsa encrypt <p> <q> <string>\n"
              << "./Cryptolib rsa decrypt <p> <q> <string>\n";
}

int main(int argc, char* argv[]) {

    if (argc < 2)
    {
        print_usage();
        return 1;
    }

    std::string cmd = argv[1];

    // MD5 ------------------

    if (cmd == "md5" && argc == 3)
    {
        const char* s = argv[2];
        auto hash = MD5(reinterpret_cast<const uint8_t*>(s), std::strlen(s));
        std::cout << md5hash_to_string(hash.data()) << std::endl;
        return 0;
    }

    // SHA1 ------------------

    if (cmd == "sha1" && argc == 3)
    {
        const char* s = argv[2];
        auto hash = SHA1(reinterpret_cast<const uint8_t*>(s), std::strlen(s));
        std::cout << sha1_to_hex(hash.data()) << std::endl;
        return 0;
    }

    // KEY GENERATOR ------------------

    if (cmd == "keygen" && argc == 3)
    {
        size_t len = std::stoul(argv[2]);
        auto key = generateKey(len);
        print_hex_key(key);
        return 0;
    }

    // HMAC-MD5 ------------------

    if (cmd == "hmac-md5" && argc == 4)
    {
        std::string keyStr = argv[2];
        std::vector<uint8_t> key(keyStr.begin(), keyStr.end());
        const char* msg = argv[3];
        auto mac = hmac_md5(key, reinterpret_cast<const uint8_t*>(msg), std::strlen(msg));
        std::cout << md5hash_to_string(mac.data()) << std::endl;
        return 0;
    }

    // HMAC-SHA1 ------------------

    if (cmd == "hmac-sha1" && argc == 4)
    {
        std::string keyStr = argv[2];
        std::vector<uint8_t> key(keyStr.begin(), keyStr.end());
        const char* msg = argv[3];
        auto mac = hmac_sha1(key, reinterpret_cast<const uint8_t*>(msg), std::strlen(msg));
        std::cout << sha1_to_hex(mac.data()) << std::endl;
        return 0;
    }

    // RSA ------------------

    if (cmd == "rsa" && argc >= 3) {
        std::string sub = argv[2];

        if (sub == "gen" && argc == 5) {
            uint64_t p = std::stoull(argv[3]);
            uint64_t q = std::stoull(argv[4]);
            RSA rsa(p, q);
            auto pub  = rsa.publicKey();
            auto priv = rsa.privateKey();
            std::cout << "n = " << pub.first << ", e = " << pub.second
                      << ", d = " << priv.second << std::endl;
            return 0;
        }

        if (sub == "encrypt" && argc == 6) {
            uint64_t p = std::stoull(argv[3]);
            uint64_t q = std::stoull(argv[4]);
            std::string msg = argv[5];
            RSA rsa(p, q);
            auto cipher = rsa.encrypt(msg);
            for (auto c : cipher) std::cout << c << ' ';
            std::cout << std::endl;
            return 0;
        }

        if (sub == "decrypt" && argc >= 6) {
            uint64_t p = std::stoull(argv[3]);
            uint64_t q = std::stoull(argv[4]);
            std::vector<uint64_t> cipher;
            for (int i = 5; i < argc; ++i) cipher.push_back(std::stoull(argv[i]));
            RSA rsa(p, q);
            std::cout << rsa.decrypt(cipher) << std::endl;
            return 0;
        }
    }

    print_usage();
    
    return 0;
}
