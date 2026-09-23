#pragma once
#include <string>
#include "credential/ICredential.h"
#include "crypto/IAsymmetricCrypto.h"
#include "identity/DID.h"
#include "identity/DIDResolver.h"
#include "zkp/IZKP.h"

class IVerifier {
public:
    virtual ~IVerifier() = default;
    virtual const DID& getDID() const = 0;
    virtual bool verifyCredential(const ICredential& credential, const DIDResolver& resolver, const IAsymmetricCrypto& crypto) const = 0;
    virtual bool verifyZKProof(const ZKPProofData& proof, long long publicValue, const std::string& statement, const IZKP& zkp) const = 0;
};
