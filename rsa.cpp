#pragma once

#include "rsa.h"


RSA::RSA(uint64_t p, uint64_t q)
{
    if (!isPrime(p) || !isPrime(q) || p == q)
    {
        throw std::runtime_error("p and q must be different primes");
    }

    n = p * q;
    phi = (p - 1) * (q - 1);

    for (e = 3; e < phi; e += 2)
    {
        if (gcd(e, phi) == 1) break;
    }

    d = modInverse(e, phi);
}

std::pair<uint64_t, uint64_t> RSA::publicKey() const
{
    return {n, e};
}

std::pair<uint64_t, uint64_t> RSA::privateKey() const
{
    return {n, d};
}

bool RSA::isPrime(uint64_t x)
{
    if (x < 2) return false;

    for (uint64_t i = 2, r = std::sqrt(x); i <= r; ++i)
    {
        if (x % i == 0) return false;
    }
    return true;
}

uint64_t RSA::gcd(uint64_t a, uint64_t b)
{
    while (b)
    {
        uint64_t tmp = a % b;
        a = b;
        b = tmp;
    }
    return a;
}

uint64_t RSA::modPow(uint64_t base, uint64_t exp, uint64_t mod)
{
    uint64_t res = 1;
    while (exp)
    {
        if (exp & 1)
        {
            res = (__uint128_t)res * base % mod;
        }
        base = (__uint128_t)base * base % mod;
        exp >>= 1;
    }
    return res;
}

uint64_t RSA::modInverse(uint64_t e, uint64_t phi)
{
    int64_t t = 0,  newT = 1;
    int64_t r = static_cast<int64_t>(phi);
    int64_t newR = static_cast<int64_t>(e);

    while (newR != 0)
    {
        uint64_t q = r / newR;
        std::tie(t, newT) = std::make_pair(newT, t - q*newT);
        std::tie(r, newR) = std::make_pair(newR, r - q*newR);
    }

    if (r != 1)
    {
        throw std::runtime_error("e and phi must be coprime");
    }

    if (t < 0)
    {
        t += phi;
    }

    return static_cast<uint64_t>(t);
}

std::vector<uint64_t> RSA::encrypt(const std::string& plaintext) const
{
    std::vector<uint64_t> out;
    out.reserve(plaintext.size());
    for (unsigned char ch : plaintext)
    {
        out.push_back(modPow(ch, e, n));
    }
    return out;
}

std::string RSA::decrypt(const std::vector<uint64_t>& ciphertext) const
{
    std::string out;
    out.reserve(ciphertext.size());
    for (auto c : ciphertext)
    {
        out.push_back(static_cast<char>(modPow(c, d, n)));
    }
    return out;
}