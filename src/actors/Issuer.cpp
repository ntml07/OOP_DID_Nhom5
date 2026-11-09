#include "actors/Issuer.h"

#include "identity/VerificationMethod.h"

Issuer::Issuer(
    const DID& did,
    IAsymmetricCrypto& crypto,
    const std::string& verificationMethodId
)
    : did(did),
    crypto(crypto),
    verificationMethodId(verificationMethodId)
{
}

const DID& Issuer::getDID() const
{
    return did;
}

std::string Issuer::getPublicKey() const
{
    return crypto.getPublicKey();
}

DIDDocument Issuer::createDidDocument() const
{
    // Main block: gắn khóa công khai RSA vào DID Document của Issuer
    DIDDocument document(did);
    document.addVerificationMethod(VerificationMethod(
        verificationMethodId,
        "RsaVerificationKey",
        did.toString(),
        getPublicKey()));
    return document;
}

VerifiableCredential Issuer::issueCredential(
    const std::string& credentialId,
    const CredentialSubject& subject,
    const std::string& issuanceDate
)
{
    VerifiableCredential vc(
        credentialId,
        did.toString(),
        subject,
        issuanceDate
    );

    std::string data = vc.serializeForSigning();

    DigitalSignature signature = crypto.sign(
        data,
        verificationMethodId
    );

    vc.setSignature(signature);

    // Main block: track issued IDs for later Issuer-side revoke lookup
    issuedCredentialIds.insert(credentialId);
    revokedCredentialIds.erase(credentialId);

    return vc;
}

bool Issuer::revokeCredential(const std::string& credentialId)
{
    // Main block: only revoke IDs this Issuer actually issued; do not alter VC payload
    if (issuedCredentialIds.find(credentialId) == issuedCredentialIds.end())
    {
        return false;
    }
    if (revokedCredentialIds.find(credentialId) != revokedCredentialIds.end())
    {
        return false;
    }

    revokedCredentialIds.insert(credentialId);
    return true;
}

bool Issuer::isRevoked(const std::string& credentialId) const
{
    return revokedCredentialIds.find(credentialId) != revokedCredentialIds.end();
}
