#pragma once
#include "actors/IVerifier.h"

class Verifier : public IVerifier {
private:
    DID did;
public:
    explicit Verifier(const DID& did);
    const DID& getDID() const override;
    bool verifyCredential(const ICredential& credential, const DIDResolver& resolver, const IAsymmetricCrypto& crypto) const override;
    bool verifyZKProof(const ZKPProofData& proof, long long publicValue, const std::string& statement, const IZKP& zkp) const override;
};
