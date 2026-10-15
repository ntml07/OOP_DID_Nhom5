#include "actors/Issuer.h"

#include "actors/Issuer.h"

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

    return vc;
}
