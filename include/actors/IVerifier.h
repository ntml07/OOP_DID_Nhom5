#pragma once
#include <string>
#include "actors/IIssuer.h"
#include "credential/VerifiableCredential.h"
#include "crypto/IAsymmetricCrypto.h"
#include "identity/DID.h"
#include "identity/DIDResolver.h"
#include "zkp/IZKP.h"

class IVerifier {
public:
    virtual ~IVerifier() = default;
    virtual const DID& getDID() const = 0;

    // RSA: verify Issuer signature on VC (+ Issuer in-memory revocation list)
    virtual bool verifyCredential(
        const VerifiableCredential& credential,
        const DIDResolver& resolver,
        const IAsymmetricCrypto& crypto,
        const IIssuer& issuer) const = 0;

    // Low-level ZKP (statement + publicValue already known)
    virtual bool verifyZKProof(
        const ZKPProofData& proof,
        long long publicValue,
        const std::string& statement,
        const IZKP& zkp) const = 0;

    // ZKP only: Holder DID control vs credentialSubject.id (no RSA inside)
    virtual bool verifyHolderControl(
        const VerifiableCredential& credential,
        const ZKPProofData& proof,
        const std::string& claimedHolderDid,
        const std::string& sessionChallenge,
        const DIDResolver& resolver,
        const IZKP& zkp) const = 0;
};
