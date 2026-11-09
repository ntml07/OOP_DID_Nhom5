#include "actors/Holder.h"

#include <iostream>

#include "identity/VerificationMethod.h"

namespace {

constexpr long long kSchnorrQ = 11;

bool isValidSchnorrSecret(long long secret)
{
    long long x = secret % kSchnorrQ;
    if (x < 0)
    {
        x += kSchnorrQ;
    }

    return x != 0;
}

std::string makeControlStatement(
    const std::string& sessionChallenge,
    const std::string& holderDid)
{
    return sessionChallenge + "|control:" + holderDid;
}
}

Holder::Holder(const DID& did)
    : did(did),
      schnorrSecret(0),
      hasSchnorrSecret(false)
{
}

const DID& Holder::getDID() const
{
    return did;
}

void Holder::receiveCredential(
    const VerifiableCredential& credential)
{
    credentials.push_back(credential);
}

const std::vector<VerifiableCredential>&
Holder::getCredentials() const
{
    return credentials;
}

const VerifiableCredential*
Holder::findCredential(const std::string& credentialId) const
{
    for (const auto& credential : credentials)
    {
        if (credential.getId() == credentialId)
        {
            return &credential;
        }
    }
    return nullptr;
}

void Holder::setSchnorrSecret(long long secret)
{
    if (!isValidSchnorrSecret(secret))
    {
        hasSchnorrSecret = false;
        schnorrSecret = 0;
        return;
    }
    schnorrSecret = secret;
    hasSchnorrSecret = true;
}

std::string Holder::getSchnorrMethodId() const
{
    return did.getValue() + "#schnorr-1";
}

long long Holder::createSchnorrPublicValue(const IZKP& zkp) const
{
    if (!hasSchnorrSecret)
    {
        return 0;
    }
    return zkp.createPublicValue(schnorrSecret);
}

ZKPProofData Holder::createOwnershipProof(
    const IZKP& zkp,
    const std::string& sessionChallenge) const
{
    ZKPProofData emptyProof{};
    if (!hasSchnorrSecret || sessionChallenge.empty())
    {
        return emptyProof;
    }

    const std::string statement =
        makeControlStatement(sessionChallenge, did.getValue());

    return zkp.generateProof(schnorrSecret, statement);
}

void Holder::showWallet() const
{
    // Main block: in các VC đang giữ trong ví
    if (credentials.empty())
    {
        std::cout << "Vi dang trong.\n";
        return;
    }

    std::cout << "Vi chung chi (" << credentials.size() << "):\n";
    for (size_t i = 0; i < credentials.size(); ++i)
    {
        const VerifiableCredential& vc = credentials[i];
        std::cout << "  " << (i + 1) << ") ID=" << vc.getId()
                  << " | issuer=" << vc.getIssuerDID()
                  << " | subject=" << vc.getSubject().getDID().getValue()
                  << " | status=" << vc.getStatus().toString();
        if (vc.getSubject().hasClaim("name"))
        {
            std::cout << " | name=" << vc.getSubject().getClaim("name");
        }
        std::cout << "\n";
    }
}

DIDDocument Holder::createDidDocument(const IZKP& zkp) const
{
    // Main block: gắn public value Schnorr vào DID Document của Holder
    DIDDocument document(did);
    const long long publicValue = createSchnorrPublicValue(zkp);
    document.addVerificationMethod(VerificationMethod(
        getSchnorrMethodId(),
        "SchnorrVerificationKey",
        did.toString(),
        std::to_string(publicValue)));
    return document;
}
