#pragma once
#include <string>
#include "credential/CredentialSubject.h"
#include "credential/VerifiableCredential.h"
#include "identity/DID.h"

class IIssuer {
public:
    virtual ~IIssuer() = default;
    virtual const DID& getDID() const = 0;
    virtual std::string getPublicKey() const = 0;
    virtual VerifiableCredential issueCredential(const std::string& credentialId, const CredentialSubject& subject, const std::string& issuanceDate) = 0;
    virtual bool revokeCredential(const std::string& credentialId) = 0;
    virtual bool isRevoked(const std::string& credentialId) const = 0;
};
