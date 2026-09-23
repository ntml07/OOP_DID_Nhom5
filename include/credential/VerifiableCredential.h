#pragma once
#include <string>
#include "credential/ICredential.h"

class VerifiableCredential : public ICredential {
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
    VerifiableCredential(const std::string& id, const std::string& issuerDID, const CredentialSubject& subject, const std::string& issuanceDate, const std::string& type = "VerifiableCredential");
    std::string getId() const override;
    std::string getIssuerDID() const override;
    const CredentialSubject& getSubject() const override;
    const CredentialStatus& getStatus() const override;
    const DigitalSignature& getSignature() const override;
    std::string getType() const;
    std::string getIssuanceDate() const;
    void setSignature(const DigitalSignature& signature);
    bool hasSignature() const;
    std::string serializeForSigning() const override;
    void activate();
    void suspend();
    void revoke();
    void display() const;
};
