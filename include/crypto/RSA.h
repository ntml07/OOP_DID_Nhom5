#pragma once
#include <string>
#include "crypto/IAsymmetricCrypto.h"

class RSA : public IAsymmetricCrypto {
private:
    std::string publicKey;
    std::string privateKey;
public:
    RSA();
    void generateKeyPair() override;
    std::string getPublicKey() const override;
    DigitalSignature sign(const std::string& data, const std::string& keyId) const override;
    bool verify(const std::string& data, const DigitalSignature& signature, const std::string& publicKey) const override;
    std::string getAlgorithmName() const override;
};
