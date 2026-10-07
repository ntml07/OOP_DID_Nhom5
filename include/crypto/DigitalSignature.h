#pragma once
#include <string>

class DigitalSignature {
private:
    std::string algorithm;
    std::string keyId;
    std::string value;

public:
    DigitalSignature();
    DigitalSignature(const std::string& algo, const std::string& kId, const std::string& val);

    std::string getAlgorithm() const;
    void setAlgorithm(const std::string& algo);

    std::string getKeyId() const;
    void setKeyId(const std::string& kId);

    std::string getValue() const;
    void setValue(const std::string& val);

    bool isEmpty() const;
};