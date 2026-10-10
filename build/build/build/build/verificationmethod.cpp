
#include "identity/VerificationMethod.h"
#include <string>

VerificationMethod::VerificationMethod()
    : id(""), type(""), controller(""), publicKey("") {}

VerificationMethod::VerificationMethod(const std::string& id,
                                       const std::string& type,
                                       const std::string& controller,
                                       const std::string& publicKey)
    : id(id),
      type(type),
      controller(controller),
      publicKey(publicKey) {}

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

bool VerificationMethod::isValid() const {
    return !id.empty()
        && !type.empty()
        && !controller.empty()
        && !publicKey.empty();
}
