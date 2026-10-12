#pragma once
#include <string>

class DigitalSignature {
private:
    std::string algorithm;
    std::string keyId;
    std::string value;
public:
    DigitalSignature();
    DigitalSignature(const std::string& algorithm, const std::string& keyId, const std::string& value);
    std::string getAlgorithm() const;
    std::string getKeyId() const;
    std::string getValue() const;
    bool empty() const;
};
