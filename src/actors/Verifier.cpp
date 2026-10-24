#include "actors/Verifier.h"
#include "identity/DIDDocument.h"
#include "identity/VerificationMethod.h"

#include <string>

namespace {

std::string makeControlStatement(
    const std::string& sessionChallenge,
    const std::string& holderDid)
{
    return sessionChallenge + "|control:" + holderDid;
}

std::string makeSchnorrMethodId(const std::string& holderDid)
{
    return holderDid + "#schnorr-1";
}

bool parsePublicValue(const std::string& text, long long& out)
{
    if (text.empty())
    {
        return false;
    }
    try
    {
        size_t pos = 0;
        out = std::stoll(text, &pos);
        if (pos != text.size())
        {
            return false;
        }
    }
    catch (...)
    {
        return false;
    }
    return out > 0;
}

}
Verifier::Verifier(const DID& did)
    : did(did)
{
}

const DID& Verifier::getDID() const
{
    return did;
}

bool Verifier::verifyCredential(
    const VerifiableCredential& credential,
    const DIDResolver& resolver,
    const IAsymmetricCrypto& crypto,
    const IIssuer& issuer
) const
{
    // Main block: reject non-VALID local status (e.g. SUSPENDED demo)
    if (!credential.getStatus().isValid())
    {
        return false;
    }

    // Main block: Issuer-managed revocation (does not mutate signed VC)
    if (credential.getIssuerDID() != issuer.getDID().getValue())
    {
        return false;
    }
    if (issuer.isRevoked(credential.getId()))
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

bool Verifier::verifyHolderControl(
    const VerifiableCredential& credential,
    const ZKPProofData& proof,
    const std::string& claimedHolderDid,
    const std::string& sessionChallenge,
    const DIDResolver& resolver,
    const IZKP& zkp
) const
{

    if (claimedHolderDid.empty() || sessionChallenge.empty())
    {
        return false;
    }

    if (claimedHolderDid != credential.getSubject().getDID().getValue())
    {
        return false;
    }

    const DIDDocument* holderDoc = resolver.resolve(claimedHolderDid);
    if (holderDoc == nullptr)
    {
        return false;
    }

    const std::string expectedMethodId = makeSchnorrMethodId(claimedHolderDid);
    const VerificationMethod* method =
        holderDoc->findVerificationMethod(expectedMethodId);
    if (method == nullptr)
    {
        return false;
    }

    if (method->getId() != expectedMethodId)
    {
        return false;
    }
    if (method->getController() != claimedHolderDid)
    {
        return false;
    }
    if (method->getType() != "SchnorrVerificationKey")
    {
        return false;
    }

    long long publicValue = 0;
    if (!parsePublicValue(method->getPublicKey(), publicValue))
    {
        return false;
    }

    const std::string statement =
        makeControlStatement(sessionChallenge, claimedHolderDid);

    return zkp.verifyProof(proof, publicValue, statement);
}
