#include <iostream>
#include <cassert>

#include "actors/Holder.h"
#include "actors/Issuer.h"
#include "credential/CredentialSubject.h"
#include "credential/VerifiableCredential.h"
#include "crypto/RSA.h"
#include "identity/DID.h"

void testHolder()
{
    // Main block: Holder receive / find / miss credential
    std::cout << "Test 1: Holder\n";

    DID holderDID("did:example:holder001");
    CredentialSubject subject(holderDID);
    subject.addClaim("name", "Alice");

    VerifiableCredential vc(
        "vc:001",
        "did:example:issuer001",
        subject,
        "2024-01-01");

    Holder holder(holderDID);
    holder.receiveCredential(vc);

    assert(holder.getDID().getValue() == "did:example:holder001");
    assert(holder.getCredentials().size() == 1);

    const VerifiableCredential* found = holder.findCredential("vc:001");
    assert(found != nullptr);
    assert(found->getId() == "vc:001");
    assert(found->getSubject().getClaim("name") == "Alice");

    const VerifiableCredential* notFound = holder.findCredential("vc:999");
    assert(notFound == nullptr);

    std::cout << "Holder: PASSED\n\n";
}

void testIssuer()
{
    // Main block: Issuer issueCredential and attach signature
    std::cout << "Test 2: Issuer\n";

    DID issuerDID("did:example:issuer001");
    DID holderDID("did:example:holder001");

    CredentialSubject subject(holderDID);
    subject.addClaim("name", "Alice");
    subject.addClaim("membership", "active");

    RSA crypto;
    crypto.generateKeyPair();

    Issuer issuer(
        issuerDID,
        crypto,
        "did:example:issuer001#key-1");

    VerifiableCredential vc = issuer.issueCredential(
        "vc:002",
        subject,
        "2024-01-01");

    assert(issuer.getDID().getValue() == "did:example:issuer001");
    assert(vc.getId() == "vc:002");
    assert(vc.getIssuerDID() == issuerDID.toString());
    assert(vc.getSubject().getClaim("name") == "Alice");
    assert(vc.hasSignature() == true);
    assert(vc.getSignature().getKeyId() == "did:example:issuer001#key-1");
    assert(vc.getStatus().isValid() == true);

    std::cout << "Issuer: PASSED\n\n";
}

int main()
{
    std::cout << "===== TEST ACTORS MODULE =====\n\n";

    testHolder();
    testIssuer();

    // Verifier tests: add after Verifier.cpp is implemented
    std::cout << "===== ALL ACTORS TESTS PASSED =====\n";
    return 0;
}
