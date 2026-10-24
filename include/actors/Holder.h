#pragma once
#include <string>
#include <vector>
#include "actors/IHolder.h"

class Holder : public IHolder {
private:
    DID did;
    std::vector<VerifiableCredential> credentials;
    long long schnorrSecret;
    bool hasSchnorrSecret;
public:
    Holder(const DID& did);
    const DID& getDID() const override;
    void receiveCredential(const VerifiableCredential& credential) override;
    const std::vector<VerifiableCredential>& getCredentials() const override;
    const VerifiableCredential* findCredential(const std::string& credentialId) const override;

    void setSchnorrSecret(long long secret) override;
    std::string getSchnorrMethodId() const override;
    long long createSchnorrPublicValue(const IZKP& zkp) const override;
    ZKPProofData createOwnershipProof(
        const IZKP& zkp,
        const std::string& sessionChallenge) const override;
};
