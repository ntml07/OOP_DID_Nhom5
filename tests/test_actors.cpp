#include "actors/Issuer.h"
#include "actors/Holder.h"
#include "credential/CredentialSubject.h"
#include "credential/VerifiableCredential.h"
#include "identity/DID.h"
#include "crypto/RSA.h"
#include <cassert>
#include <iostream>

void testHolder()
{
    DID holderDID("did:example:holder");
    DID subjectDID("did:example:subject");

    CredentialSubject subject(subjectDID);
    subject.addClaim("name", "Test User");

    VerifiableCredential vc(
        "vc001",
        "did:example:issuer",
        subject,
        "2026-10-13",
        "UniversityCredential"
    );

    Holder holder(holderDID);
    holder.receiveCredential(vc);

    assert(holder.getCredentials().size() == 1);

    const VerifiableCredential* found =
        holder.findCredential("vc001");

    assert(found != nullptr);
    assert(found->getId() == "vc001");

    const VerifiableCredential* notFound =
        holder.findCredential("vc999");

    assert(notFound == nullptr);

    std::cout << "Holder tests passed!" << std::endl;
}

void testIssuer()
{
    DID issuerDID("did:example:issuer");
    DID subjectDID("did:example:subject");

    CredentialSubject subject(subjectDID);
    subject.addClaim("name", "Test User");

    RSA crypto;
    crypto.generateKeyPair();

    Issuer issuer(
        issuerDID,
        crypto,
        "did:example:issuer#key-1"
    );

    VerifiableCredential vc = issuer.issueCredential(
        "vc002",
        subject,
        "2026-10-14"
    );

    assert(vc.getId() == "vc002");
    assert(vc.getIssuerDID() == issuerDID.toString());
    assert(vc.hasSignature() == true);

    std::cout << "Issuer tests passed!" << std::endl;
}

int main()
{
    testHolder();
    testIssuer();
    return 0;
}

