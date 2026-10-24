#pragma once
#include "actors/IVerifier.h"

class Verifier : public IVerifier {
private:
    DID did;
public:
    Verifier(const DID& did);
    const DID& getDID() const override;
    bool verifyCredential(
        const VerifiableCredential& credential,
        const DIDResolver& resolver,
        const IAsymmetricCrypto& crypto,
        const IIssuer& issuer) const override;
    bool verifyZKProof(
        const ZKPProofData& proof,
        long long publicValue,
        const std::string& statement,
        const IZKP& zkp) const override;
    bool verifyHolderControl(
        const VerifiableCredential& credential,
        const ZKPProofData& proof,
        const std::string& claimedHolderDid,
        const std::string& sessionChallenge,
        const DIDResolver& resolver,
        const IZKP& zkp) const override;
};
