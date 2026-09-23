#pragma once
#include <string>
#include "credential/CredentialSubject.h"
#include "credential/CredentialStatus.h"
#include "crypto/DigitalSignature.h"

class ICredential {
public:
    virtual ~ICredential() = default;
    virtual std::string getId() const = 0;
    virtual std::string getIssuerDID() const = 0;
    virtual const CredentialSubject& getSubject() const = 0;
    virtual const CredentialStatus& getStatus() const = 0;
    virtual const DigitalSignature& getSignature() const = 0;
    virtual std::string serializeForSigning() const = 0;
};
