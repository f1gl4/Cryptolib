#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <cmath>
#include <stdexcept>
#include <tuple>

class RSA
{
public:
    /**
     * \brief Create RSA keys from two primes
     */
    RSA(uint64_t p, uint64_t q);

    // Public key (n, e)
    std::pair<uint64_t, uint64_t> publicKey() const;

    // Private key (n, d)
    std::pair<uint64_t, uint64_t> privateKey() const;

    // Encrypt ASCII text
    std::vector<uint64_t> encrypt(const std::string& plaintext) const;

    // Decrypt vector back to ASCII string
    std::string decrypt(const std::vector<uint64_t>& ciphertext) const;


private:
    uint64_t n{};
    uint64_t phi{};
    uint64_t e{};
    uint64_t d{};

    // Primality test
    static bool isPrime(uint64_t x);

    // Euclidean GCD
    static uint64_t gcd(uint64_t a, uint64_t b);

    // base ^ exp mod mod
    static uint64_t modPow(uint64_t base, uint64_t exp, uint64_t mod);

    // Extended Euclid: e^(-1) mod phi
    static uint64_t modInverse(uint64_t e, uint64_t phi);
};