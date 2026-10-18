
#include "actors/Verifier.h"
#include "identity/DIDDocument.h"
#include "identity/VerificationMethod.h"

Verifier::Verifier(const DID& did)
    : did(did)
{
}

const DID& Verifier::getDID() const
{
    return did;
}

bool Verifier::verifyCredential(
    const ICredential& credential,
    const DIDResolver& resolver,
    const IAsymmetricCrypto& crypto
) const
{
    if (!credential.getStatus().isValid())
    {
        return false;
    }

    const DigitalSignature& signature = credential.getSignature();

    if (signature.empty())
    {
        return false;
    }

    const DIDDocument* document =
        resolver.resolve(credential.getIssuerDID());

    if (document == nullptr)
    {
        return false;
    }

    const VerificationMethod* method =
        document->findVerificationMethod(signature.getKeyId());

    if (method == nullptr)
    {
        return false;
    }

    const std::string publicKey = method->getPublicKey();

    if (publicKey.empty())
    {
        return false;
    }

    return crypto.verify(
        credential.serializeForSigning(),
        signature,
        publicKey
    );
}

bool Verifier::verifyZKProof(
    const ZKPProofData& proof,
    long long publicValue,
    const std::string& statement,
    const IZKP& zkp
) const
{
    return zkp.verifyProof(
        proof,
        publicValue,
        statement
    );
}
