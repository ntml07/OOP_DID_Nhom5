#pragma once
#include <set>
#include <string>
#include "actors/IIssuer.h"
#include "crypto/IAsymmetricCrypto.h"

class Issuer : public IIssuer {
private:
    DID did;
    IAsymmetricCrypto& crypto;
    std::string verificationMethodId;
    std::set<std::string> issuedCredentialIds;
    std::set<std::string> revokedCredentialIds;
public:
    Issuer(const DID& did, IAsymmetricCrypto& crypto, const std::string& verificationMethodId);
    const DID& getDID() const override;
    std::string getPublicKey() const override;
    VerifiableCredential issueCredential(const std::string& credentialId, const CredentialSubject& subject, const std::string& issuanceDate) override;
    bool revokeCredential(const std::string& credentialId) override;
    bool isRevoked(const std::string& credentialId) const override;
};
