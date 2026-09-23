#pragma once
#include <string>

class VerificationMethod {
private:
    std::string id;
    std::string type;
    std::string controller;
    std::string publicKey;
public:
    VerificationMethod(const std::string& id, const std::string& type, const std::string& controller, const std::string& publicKey);
    std::string getId() const;
    std::string getType() const;
    std::string getController() const;
    std::string getPublicKey() const;
};
