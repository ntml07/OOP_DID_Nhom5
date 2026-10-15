#include "crypto/RSA.h"

RSA::RSA() {
    publicKey = "";
    privateKey = "";
}
void RSA::generateKeyPair() {
    publicKey = "RSA_PUB_KEY_DEMO_123";
    privateKey = "RSA_PRIV_KEY_DEMO_123";
}
std::string RSA::getPublicKey() const {
    return publicKey;
}
DigitalSignature RSA::sign(const std::string& data, const std::string& keyId) const {  
    std::string signatureValue = "SIGNED_BY_RSA_" + data;
    return DigitalSignature("SHA256withRSA", keyId, signatureValue);
}
bool RSA::verify(const std::string& data, const DigitalSignature& signature, const std::string& pubKey) const {
    if (pubKey != publicKey) {
        return false;
    }
    std::string expectedValue = "SIGNED_BY_RSA_" + data;
    if (signature.getValue() != expectedValue) {
        return false;
    }
    return true;
}
std::string RSA::getAlgorithmName() const {
    return "SHA256withRSA";
}
