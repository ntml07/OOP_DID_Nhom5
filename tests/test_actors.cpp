#include <iostream>
#include <cassert>

#include "actors/Holder.h"
#include "actors/Issuer.h"
#include "credential/CredentialSubject.h"
#include "credential/VerifiableCredential.h"
#include "crypto/RSA.h"
#include "identity/DID.h"

#include "actors/Verifier.h"
#include "zkp/SchnorrZKP.h"
#include "identity/DIDDocument.h"
#include "identity/DIDResolver.h"
#include "identity/VerificationMethod.h"

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


void testVerifier()
{
    std::cout << "Test: Verifier\n";

    DID issuerDID("did:example:issuer001");
    RSA crypto;
    crypto.generateKeyPair();

    std::string keyId = "did:example:issuer001#key-1";
    Issuer issuer(issuerDID, crypto, keyId);

    DIDDocument document(issuerDID);
    document.addVerificationMethod(VerificationMethod(
        keyId, "RsaVerificationKey",
        issuerDID.toString(), issuer.getPublicKey()
    ));

    DIDResolver resolver;
    resolver.registerDocument(document);

    Verifier verifier(DID("did:example:verifier001"));

    DID subjectDID("did:example:subject001");
    CredentialSubject subject(subjectDID);
    subject.addClaim("name", "Alice");

    VerifiableCredential vc = issuer.issueCredential(
        "vc001", subject, "2026-10-19"
    );

    assert(verifier.verifyCredential(vc, resolver, crypto));
    std::cout << "[PASS] Valid VC\n";

    VerifiableCredential revokedVC = vc;
    revokedVC.revoke();
    assert(!verifier.verifyCredential(revokedVC, resolver, crypto));
    std::cout << "[PASS] Revoked VC\n";

    VerifiableCredential suspendedVC = vc;
    suspendedVC.suspend();
    assert(!verifier.verifyCredential(suspendedVC, resolver, crypto));
    std::cout << "[PASS] Suspended VC\n";

    VerifiableCredential unknownVC(
        "vc002", "did:example:unknown001", subject, "2026-10-19"
    );
    unknownVC.setSignature(vc.getSignature());
    assert(!verifier.verifyCredential(unknownVC, resolver, crypto));
    std::cout << "[PASS] Unknown issuer DID\n";

    Issuer wrongIssuer(
        issuerDID, crypto, "did:example:issuer001#missing-key"
    );
    VerifiableCredential wrongKeyVC = wrongIssuer.issueCredential(
        "vc003", subject, "2026-10-19"
    );
    assert(!verifier.verifyCredential(wrongKeyVC, resolver, crypto));
    std::cout << "[PASS] Unknown keyId\n";

    CredentialSubject changedSubject(subjectDID);
    changedSubject.addClaim("name", "Bob");

    VerifiableCredential changedVC(
        vc.getId(), vc.getIssuerDID(), changedSubject,
        vc.getIssuanceDate(), vc.getType()
    );
    changedVC.setSignature(vc.getSignature());
    assert(!verifier.verifyCredential(changedVC, resolver, crypto));
    std::cout << "[PASS] Modified VC\n";

    DIDDocument wrongDocument(issuerDID);
    wrongDocument.addVerificationMethod(VerificationMethod(
        keyId, "RsaVerificationKey",
        issuerDID.toString(), "WRONG_PUBLIC_KEY"
    ));

    DIDResolver wrongResolver;
    wrongResolver.registerDocument(wrongDocument);

    assert(!verifier.verifyCredential(vc, wrongResolver, crypto));
    std::cout << "[PASS] Wrong public key\n";
}


void testVerifierZKP()
{
    std::cout << "Test 4: Verifier ZKP\n";

    DID verifierDID("did:example:verifier001");
    Verifier verifier(verifierDID);

    SchnorrZKP zkp;

    long long secret = 42;
    std::string statement = "prove knowledge of secret";

    long long publicValue = zkp.createPublicValue(secret);
    ZKPProofData proof = zkp.generateProof(secret, statement);

    // Test 1: Proof hop le -> true
    assert(verifier.verifyZKProof(
        proof, publicValue, statement, zkp
    ));

    std::cout << "Test 1: Valid ZKP proof PASSED\n";

    // Test 2: Proof bi sua -> false
    ZKPProofData invalidProof = proof;
    ++invalidProof.response;

    assert(!verifier.verifyZKProof(
        invalidProof, publicValue, statement, zkp
    ));

    std::cout << "Test 2: Invalid ZKP proof PASSED\n";

    // Test 3: Public value sai -> false
    assert(!verifier.verifyZKProof(
        proof, 0, statement, zkp
    ));

    std::cout << "Test 3: Wrong public value PASSED\n";

    std::cout << "Verifier ZKP tests completed.\n\n";
}

int main()
{
    testHolder();
    testIssuer();
    testVerifier();
    testVerifierZKP();

    std::cout << "All actor tests passed!\n";
    return 0;
}


