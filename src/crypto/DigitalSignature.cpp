#include "crypto/DigitalSignature.h"
DigitalSignature::DigitalSignature() 
    : algorithm(""), keyId(""), value("") {}
DigitalSignature::DigitalSignature(const std::string& algo, const std::string& kId, const std::string& val)
    : algorithm(algo), keyId(kId), value(val) {}
std::string DigitalSignature::getAlgorithm() const {
    return algorithm;
}
void DigitalSignature::setAlgorithm(const std::string& algo) {
    this->algorithm = algo;
}
std::string DigitalSignature::getKeyId() const {
    return keyId;
}
void DigitalSignature::setKeyId(const std::string& kId) {
    this->keyId = kId;
}
std::string DigitalSignature::getValue() const {
    return value;
}
void DigitalSignature::setValue(const std::string& val) {
    this->value = val;
}
bool DigitalSignature::isEmpty() const {
    return value.empty() || algorithm.empty();
}