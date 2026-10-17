#include <iostream>
#include <cassert>

#include "credential/CredentialSubject.h"
#include "credential/CredentialStatus.h"
#include "credential/VerifiableCredential.h"
#include "crypto/DigitalSignature.h"
#include "identity/DID.h"

void testSubjectAndStatus()
{
    std::cout << "Test 1: CredentialSubject + CredentialStatus\n";

    DID holderDID("did:example:holder001");
    CredentialSubject subject(holderDID);
    subject.addClaim("name", "Alice");
    subject.addClaim("membership", "active");

    assert(subject.getDID().getValue() == "did:example:holder001");
    assert(subject.getClaim("name") == "Alice");
    assert(subject.hasClaim("membership") == true);

    CredentialStatus status;
    assert(status.isValid() == true);

    status.suspend();
    assert(status.toString() == "SUSPENDED");
    assert(status.isValid() == false);

    status.revoke();
    assert(status.toString() == "REVOKED");

    status.activate();
    assert(status.isValid() == true);

    std::cout << "Subject/Status: PASSED\n\n";
}

void testVerifiableCredential()
{
    std::cout << "Test 2: VerifiableCredential\n";

    DID holderDID("did:example:holder001");
    CredentialSubject subject(holderDID);
    subject.addClaim("name", "Alice");

    VerifiableCredential vc(
        "vc:001",
        "did:example:issuer001",
        subject,
        "2024-01-01");

    assert(vc.getId() == "vc:001");
    assert(vc.getIssuerDID() == "did:example:issuer001");
    assert(vc.getSubject().getClaim("name") == "Alice");
    assert(vc.getStatus().isValid() == true);
    assert(vc.hasSignature() == false);

    std::string payload1 = vc.serializeForSigning();
    std::string payload2 = vc.serializeForSigning();
    assert(payload1 == payload2);

    vc.setSignature(DigitalSignature("RSA", "key-1", "SIG"));
    assert(vc.hasSignature() == true);
    assert(vc.serializeForSigning() == payload1);
    assert(payload1.find("SIG") == std::string::npos);

    vc.suspend();
    assert(vc.getStatus().toString() == "SUSPENDED");
    vc.revoke();
    assert(vc.getStatus().toString() == "REVOKED");

    std::cout << "VC: PASSED\n\n";
}

int main()
{
    std::cout << "===== TEST CREDENTIAL MODULE =====\n\n";

    testSubjectAndStatus();
    testVerifiableCredential();

    std::cout << "===== ALL CREDENTIAL TESTS PASSED =====\n";
    return 0;
}
