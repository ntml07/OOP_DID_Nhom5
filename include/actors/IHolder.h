#pragma once
#include <string>
#include <vector>
#include "credential/VerifiableCredential.h"
#include "identity/DID.h"
#include "zkp/IZKP.h"

class IHolder {
public:
    virtual ~IHolder() = default;
    virtual const DID& getDID() const = 0;
    virtual void receiveCredential(const VerifiableCredential& credential) = 0;
    virtual const std::vector<VerifiableCredential>& getCredentials() const = 0;
    virtual const VerifiableCredential* findCredential(const std::string& credentialId) const = 0;

    // Schnorr DID-control (secret stays inside Holder only)
    virtual void setSchnorrSecret(long long secret) = 0;
    virtual std::string getSchnorrMethodId() const = 0;
    virtual long long createSchnorrPublicValue(const IZKP& zkp) const = 0;
    virtual ZKPProofData createOwnershipProof(
        const IZKP& zkp,
        const std::string& sessionChallenge) const = 0;
};
