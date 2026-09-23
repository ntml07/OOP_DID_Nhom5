#pragma once
#include <string>
#include <vector>
#include "actors/IHolder.h"

class Holder : public IHolder {
private:
    DID did;
    std::vector<VerifiableCredential> credentials;
public:
    explicit Holder(const DID& did);
    const DID& getDID() const override;
    void receiveCredential(const VerifiableCredential& credential) override;
    const std::vector<VerifiableCredential>& getCredentials() const override;
    const VerifiableCredential* findCredential(const std::string& credentialId) const override;
};
