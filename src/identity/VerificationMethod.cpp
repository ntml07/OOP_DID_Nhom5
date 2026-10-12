#include "identity/VerificationMethod.h"

// Gắn id, loại thuật toán, controller và public key
VerificationMethod::VerificationMethod(const std::string& id,
                                       const std::string& type,
                                       const std::string& controller,
                                       const std::string& publicKey)
    : id(id), type(type), controller(controller), publicKey(publicKey) {}

std::string VerificationMethod::getId() const {
    return id;
}

std::string VerificationMethod::getType() const {
    return type;
}

std::string VerificationMethod::getController() const {
    return controller;
}

std::string VerificationMethod::getPublicKey() const {
    return publicKey;
}
