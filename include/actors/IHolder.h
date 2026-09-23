#pragma once
#include <string>
#include <vector>
#include "credential/VerifiableCredential.h"
#include "identity/DID.h"

class IHolder {
public:
    virtual ~IHolder() = default;
    virtual const DID& getDID() const = 0;
    virtual void receiveCredential(const VerifiableCredential& credential) = 0;
    virtual const std::vector<VerifiableCredential>& getCredentials() const = 0;
    virtual const VerifiableCredential* findCredential(const std::string& credentialId) const = 0;
};
