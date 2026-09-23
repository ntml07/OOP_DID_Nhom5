#pragma once
#include <string>
#include "crypto/DigitalSignature.h"

class IAsymmetricCrypto {
public:
    virtual ~IAsymmetricCrypto() = default;
    virtual void generateKeyPair() = 0;
    virtual std::string getPublicKey() const = 0;
    virtual DigitalSignature sign(const std::string& data, const std::string& keyId) const = 0;
    virtual bool verify(const std::string& data, const DigitalSignature& signature, const std::string& publicKey) const = 0;
    virtual std::string getAlgorithmName() const = 0;
};
