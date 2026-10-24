#pragma once
#include <string>
#include "credential/CredentialSubject.h"
#include "credential/CredentialStatus.h"
#include "crypto/DigitalSignature.h"

class VerifiableCredential {
private:
    std::string context;
    std::string id;
    std::string type;
    std::string issuerDID;
    std::string issuanceDate;
    CredentialSubject subject;
    CredentialStatus status;
    DigitalSignature signature;
public:
    VerifiableCredential(
        const std::string& id,
        const std::string& issuerDID,
        const CredentialSubject& subject,
        const std::string& issuanceDate,
        const std::string& type = "VerifiableCredential");

    std::string getId() const;
    std::string getIssuerDID() const;
    const CredentialSubject& getSubject() const;
    const CredentialStatus& getStatus() const;
    const DigitalSignature& getSignature() const;
    std::string getType() const;
    std::string getIssuanceDate() const;
    void setSignature(const DigitalSignature& signature);
    bool hasSignature() const;
    std::string serializeForSigning() const;
    void activate();
    void suspend();
    void revoke();
    void display() const;
};
