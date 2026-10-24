#include "crypto/RSA.h"

#include <cstdlib>
#include <ctime>
#include <numeric>
#include <stdexcept>
#include <string>

namespace {

const std::string kAlgorithmName = "RSA-Educational";

struct NumericKey {
    long long modulus;
    long long exponent;
};

long long modNormalize(long long value, long long modulus)
{
    long long r = value % modulus;
    if (r < 0) {
        r += modulus;
    }
    return r;
}

bool isPrime(long long n)
{
    if (n < 2) {
        return false;
    }
    if (n % 2 == 0) {
        return n == 2;
    }
    for (long long i = 3; i * i <= n; i += 2) {
        if (n % i == 0) {
            return false;
        }
    }
    return true;
}

long long nextPrime(long long start)
{
    long long n = start;
    if (n < 2) {
        n = 2;
    }
    if (n % 2 == 0 && n != 2) {
        n++;
    }
    while (!isPrime(n)) {
        n += 2;
    }
    return n;
}

long long modPow(long long base, long long exp, long long modulus)
{
    long long result = 1 % modulus;
    long long current = modNormalize(base, modulus);
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * current) % modulus;
        }
        current = (current * current) % modulus;
        exp /= 2;
    }
    return result;
}

long long modInverse(long long a, long long mod)
{
    long long oldR = modNormalize(a, mod);
    long long r = mod;
    long long oldS = 1;
    long long s = 0;

    while (r != 0) {
        long long q = oldR / r;
        long long nextR = oldR - q * r;
        oldR = r;
        r = nextR;

        long long nextS = oldS - q * s;
        oldS = s;
        s = nextS;
    }

    if (oldR != 1) {
        return -1;
    }
    return modNormalize(oldS, mod);
}

long long messageToNumber(const std::string& data, long long modulus)
{
    long long h = 0;
    for (size_t i = 0; i < data.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(data[i]);
        h = (h * 31 + static_cast<long long>(c)) % modulus;
    }
    if (h == 0) {
        h = 1;
    }
    return h;
}

std::string encodeKey(long long modulus, long long exponent)
{
    return std::to_string(modulus) + "|" + std::to_string(exponent);
}

bool parseExactLongLong(const std::string& text, long long& out)
{
    if (text.empty()) {
        return false;
    }
    try {
        size_t pos = 0;
        out = std::stoll(text, &pos);
        if (pos != text.size()) {
            return false;
        }
    } catch (...) {
        return false;
    }
    return true;
}

bool parseKey(const std::string& encoded, NumericKey& key)
{
    size_t sep = encoded.find('|');
    if (sep == std::string::npos) {
        return false;
    }
    if (encoded.find('|', sep + 1) != std::string::npos) {
        return false;
    }
    if (sep == 0 || sep + 1 >= encoded.size()) {
        return false;
    }

    if (!parseExactLongLong(encoded.substr(0, sep), key.modulus)) {
        return false;
    }
    if (!parseExactLongLong(encoded.substr(sep + 1), key.exponent)) {
        return false;
    }
    if (key.modulus <= 1 || key.exponent <= 0) {
        return false;
    }
    return true;
}

long long randomInRange(long long low, long long high)
{
    return low + (std::rand() % (high - low + 1));
}

}

RSA::RSA()
{
    publicKey = "";
    privateKey = "";
}

void RSA::generateKeyPair()
{
    static bool seeded = false;
    if (!seeded) {
        std::srand(static_cast<unsigned int>(std::time(nullptr)));
        seeded = true;
    }

    long long p = 0;
    long long q = 0;
    long long n = 0;
    long long phi = 0;
    long long e = 0;
    long long d = -1;

    for (int attempt = 0; attempt < 50; ++attempt) {
        p = nextPrime(randomInRange(1009, 2999));
        q = nextPrime(randomInRange(3001, 4999));
        if (p == q) {
            continue;
        }

        n = p * q;
        phi = (p - 1) * (q - 1);

        e = 65537;
        if (e >= phi || std::gcd(e, phi) != 1) {
            e = 17;
            while (e < phi && std::gcd(e, phi) != 1) {
                e += 2;
            }
        }

        d = modInverse(e, phi);
        if (d > 0) {
            break;
        }
    }

    if (d <= 0) {
        throw std::runtime_error("RSA: cannot compute modular inverse for key pair");
    }

    publicKey = encodeKey(n, e);
    privateKey = encodeKey(n, d);
}

std::string RSA::getPublicKey() const
{
    return publicKey;
}

DigitalSignature RSA::sign(const std::string& data, const std::string& keyId) const
{
    if (privateKey.empty() || data.empty() || keyId.empty()) {
        return DigitalSignature();
    }

    NumericKey key;
    if (!parseKey(privateKey, key)) {
        return DigitalSignature();
    }

    long long message = messageToNumber(data, key.modulus);
    long long signatureValue = modPow(message, key.exponent, key.modulus);

    return DigitalSignature(
        kAlgorithmName,
        keyId,
        std::to_string(signatureValue));
}

bool RSA::verify(
    const std::string& data,
    const DigitalSignature& signature,
    const std::string& pubKey) const
{ 
    if (data.empty() || pubKey.empty() || signature.empty()) {
        return false;
    }

    if (signature.getKeyId().empty()) {
        return false;
    }

    if (signature.getAlgorithm() != kAlgorithmName) {
        return false;
    }

    NumericKey key;
    if (!parseKey(pubKey, key)) {
        return false;
    }

    long long signatureValue = 0;
    if (!parseExactLongLong(signature.getValue(), signatureValue)) {
        return false;
    }

    if (signatureValue < 0 || signatureValue >= key.modulus) {
        return false;
    }

    long long message = messageToNumber(data, key.modulus);
    long long recovered = modPow(signatureValue, key.exponent, key.modulus);

    return recovered == message;
}

std::string RSA::getAlgorithmName() const
{
    return kAlgorithmName;
}
