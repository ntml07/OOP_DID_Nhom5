#pragma once
#include <string>
#include "actors/IIssuer.h"
#include "crypto/IAsymmetricCrypto.h"

class Issuer : public IIssuer {
private:
    DID did;
    IAsymmetricCrypto& crypto;
    std::string verificationMethodId;
public:
    Issuer(const DID& did, IAsymmetricCrypto& crypto, const std::string& verificationMethodId);
    const DID& getDID() const override;
    std::string getPublicKey() const override;
    VerifiableCredential issueCredential(const std::string& credentialId, const CredentialSubject& subject, const std::string& issuanceDate) override;
};
