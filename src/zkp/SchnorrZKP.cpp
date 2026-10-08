#include "zkp/SchnorrZKP.h"

#include <cstdint>
#include <functional>
#include <random>
#include <string>

namespace {
// Demo Schnorr parameters only. Not suitable for production cryptography.
constexpr long long P = 23; // prime modulus
constexpr long long Q = 11; // subgroup order, Q divides P - 1
constexpr long long G = 2;  // generator of subgroup of order Q modulo P

long long mod(long long value, long long modulus)
{
    value %= modulus;
    return value < 0 ? value + modulus : value;
}

long long modPow(long long base, long long exponent, long long modulus)
{
    long long result = 1;
    base = mod(base, modulus);

    while (exponent > 0) {
        if (exponent & 1LL) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent >>= 1LL;
    }

    return result;
    }

long long hashToChallenge(const std::string& statement, long long commitment)
{
    const std::string input = statement + "|" + std::to_string(commitment);
    return static_cast<long long>(std::hash<std::string>{}(input) % Q);
}

long long randomNonce()
{
    static thread_local std::mt19937_64 generator(std::random_device{}());
    std::uniform_int_distribution<long long> distribution(1, Q - 1);
    return distribution(generator);
}
} // namespace

long long SchnorrZKP::createPublicValue(long long secret) const
{
    const long long x = mod(secret, Q);
    return modPow(G, x, P);
}

ZKPProofData SchnorrZKP::generateProof(
    long long secret,
    const std::string& statement) const
{
    const long long x = mod(secret, Q);
    const long long nonce = randomNonce();

    ZKPProofData proof{};
    proof.commitment = modPow(G, nonce, P);
    proof.challenge = hashToChallenge(statement, proof.commitment);
    proof.response = mod(nonce + proof.challenge * x, Q);

    return proof;
}

bool SchnorrZKP::verifyProof(
    const ZKPProofData& proof,
    long long publicValue,
    const std::string& statement) const
{
    if (publicValue <= 0 || publicValue >= P) {
        return false;
    }

    if (proof.commitment <= 0 || proof.commitment >= P) {
        return false;
    }

    const long long expectedChallenge =
        hashToChallenge(statement, proof.commitment);

    if (proof.challenge != expectedChallenge) {
        return false;
    }

    if (proof.response < 0 || proof.response >= Q) {
        return false;
    }

    // Schnorr verification:
    // g^response == commitment * publicValue^challenge (mod p)
    const long long left = modPow(G, proof.response, P);
    const long long right =
        (proof.commitment * modPow(publicValue, proof.challenge, P)) % P;

    return left == right;
}
