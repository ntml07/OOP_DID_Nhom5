#include <iostream>
#include <cassert>
#include <string>

#include "actors/Holder.h"
#include "actors/Issuer.h"
#include "actors/Verifier.h"
#include "credential/CredentialSubject.h"
#include "credential/VerifiableCredential.h"
#include "crypto/RSA.h"
#include "identity/DID.h"
#include "identity/DIDDocument.h"
#include "identity/DIDResolver.h"
#include "identity/VerificationMethod.h"
#include "zkp/SchnorrZKP.h"

void testHolder()
{
    std::cout << "Test 1: Holder\n";

    DID holderDID("did:example:holder001");
    CredentialSubject subject(holderDID);
    subject.addClaim("name", "Nguyen Van A");

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
    assert(found->getSubject().getClaim("name") == "Nguyen Van A");

    const VerifiableCredential* notFound = holder.findCredential("vc:999");
    assert(notFound == nullptr);

    std::cout << "Holder: PASSED\n\n";
}

void testIssuer()
{
    std::cout << "Test 2: Issuer\n";

    DID issuerDID("did:example:issuer001");
    DID holderDID("did:example:holder001");

    CredentialSubject subject(holderDID);
    subject.addClaim("name", "Nguyen Van A");
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
    assert(vc.getSubject().getClaim("name") == "Nguyen Van A");
    assert(vc.hasSignature() == true);
    assert(vc.getSignature().getKeyId() == "did:example:issuer001#key-1");
    assert(vc.getStatus().isValid() == true);

    std::cout << "Issuer: PASSED\n\n";
}

void testVerifier()
{
    std::cout << "Test 3: Verifier RSA\n";

    DID issuerDID("did:example:issuer001");
    RSA crypto;
    crypto.generateKeyPair();

    std::string keyId = "did:example:issuer001#key-1";
    Issuer issuer(issuerDID, crypto, keyId);

    DIDDocument document(issuerDID);
    document.addVerificationMethod(VerificationMethod(
        keyId, "RsaVerificationKey",
        issuerDID.toString(), issuer.getPublicKey()));

    DIDResolver resolver;
    resolver.registerDocument(document);

    Verifier verifier(DID("did:example:verifier001"));

    DID subjectDID("did:example:subject001");
    CredentialSubject subject(subjectDID);
    subject.addClaim("name", "Nguyen Van A");

    VerifiableCredential vc = issuer.issueCredential(
        "vc001", subject, "2026-10-19");

    assert(verifier.verifyCredential(vc, resolver, crypto, issuer));
    std::cout << "[PASS] Valid VC\n";

    // Issuer revoke: Holder copy status may stay VALID; Verifier must reject
    assert(issuer.revokeCredential(vc.getId()) == true);
    assert(vc.getStatus().isValid() == true);
    assert(!verifier.verifyCredential(vc, resolver, crypto, issuer));
    std::cout << "[PASS] Issuer-revoked VC\n";

    assert(issuer.revokeCredential("vc-never-issued") == false);
    assert(issuer.revokeCredential(vc.getId()) == false);
    std::cout << "[PASS] Revoke unknown / already-revoked ID\n";

    VerifiableCredential otherVc = issuer.issueCredential(
        "vc001-other", subject, "2026-10-19");
    assert(verifier.verifyCredential(otherVc, resolver, crypto, issuer));
    std::cout << "[PASS] Other non-revoked VC\n";

    VerifiableCredential suspendedVC = otherVc;
    suspendedVC.suspend();
    assert(!verifier.verifyCredential(suspendedVC, resolver, crypto, issuer));
    std::cout << "[PASS] Suspended VC\n";

    VerifiableCredential unknownVC(
        "vc002", "did:example:unknown001", subject, "2026-10-19");
    unknownVC.setSignature(otherVc.getSignature());
    assert(!verifier.verifyCredential(unknownVC, resolver, crypto, issuer));
    std::cout << "[PASS] Unknown issuer DID\n";

    Issuer wrongIssuer(
        issuerDID, crypto, "did:example:issuer001#missing-key");
    VerifiableCredential wrongKeyVC = wrongIssuer.issueCredential(
        "vc003", subject, "2026-10-19");
    assert(!verifier.verifyCredential(wrongKeyVC, resolver, crypto, wrongIssuer));
    std::cout << "[PASS] Unknown keyId\n";

    CredentialSubject changedSubject(subjectDID);
    changedSubject.addClaim("name", "Nguyen Thi B");

    VerifiableCredential changedVC(
        otherVc.getId(), otherVc.getIssuerDID(), changedSubject,
        otherVc.getIssuanceDate(), otherVc.getType());
    changedVC.setSignature(otherVc.getSignature());
    assert(!verifier.verifyCredential(changedVC, resolver, crypto, issuer));
    std::cout << "[PASS] Modified VC\n";

    DIDDocument wrongDocument(issuerDID);
    wrongDocument.addVerificationMethod(VerificationMethod(
        keyId, "RsaVerificationKey",
        issuerDID.toString(), "WRONG_PUBLIC_KEY"));

    DIDResolver wrongResolver;
    wrongResolver.registerDocument(wrongDocument);

    assert(!verifier.verifyCredential(otherVc, wrongResolver, crypto, issuer));
    std::cout << "[PASS] Wrong public key\n\n";
}

void testVerifierZKP()
{
    std::cout << "Test 4: Verifier low-level ZKP\n";

    Verifier verifier(DID("did:example:verifier001"));
    SchnorrZKP zkp;

    long long secret = 42;
    std::string statement = "prove knowledge of secret";

    long long publicValue = zkp.createPublicValue(secret);
    ZKPProofData proof = zkp.generateProof(secret, statement);

    assert(verifier.verifyZKProof(proof, publicValue, statement, zkp));
    std::cout << "[PASS] Valid ZKP proof\n";

    ZKPProofData invalidProof = proof;
    ++invalidProof.response;
    assert(!verifier.verifyZKProof(invalidProof, publicValue, statement, zkp));
    std::cout << "[PASS] Modified ZKP proof\n";

    assert(!verifier.verifyZKProof(proof, 0, statement, zkp));
    std::cout << "[PASS] Wrong public value\n\n";
}

void testHolderDidControl()
{
    std::cout << "Test 5: Holder DID control (ZKP)\n";

    RSA crypto;
    crypto.generateKeyPair();
    SchnorrZKP zkp;

    DID issuerDID("did:example:issuer001");
    Issuer issuer(issuerDID, crypto, "did:example:issuer001#key-1");

    DIDResolver resolver;

    DID holderDID("did:example:holder001");
    Holder holder(holderDID);
    holder.setSchnorrSecret(7);

    DIDDocument holderDoc(holderDID);
    holderDoc.addVerificationMethod(VerificationMethod(
        holder.getSchnorrMethodId(),
        "SchnorrVerificationKey",
        holderDID.toString(),
        std::to_string(holder.createSchnorrPublicValue(zkp))));
    resolver.registerDocument(holderDoc);

    CredentialSubject subject(holderDID);
    subject.addClaim("degree", "Bachelor");
    VerifiableCredential vc = issuer.issueCredential(
        "vc:degree-1", subject, "2026-10-19");
    holder.receiveCredential(vc);

    Verifier verifier(DID("did:example:verifier001"));
    const std::string session = "nonce-session-001";

    ZKPProofData proof = holder.createOwnershipProof(zkp, session);
    assert(verifier.verifyHolderControl(
        vc, proof, holderDID.getValue(), session, resolver, zkp));
    std::cout << "[PASS] Valid ownership proof\n";

    ZKPProofData tampered = proof;
    ++tampered.response;
    assert(!verifier.verifyHolderControl(
        vc, tampered, holderDID.getValue(), session, resolver, zkp));
    std::cout << "[PASS] Modified proof\n";

    DIDResolver emptyResolver;
    assert(!verifier.verifyHolderControl(
        vc, proof, holderDID.getValue(), session, emptyResolver, zkp));
    std::cout << "[PASS] Holder DID not found\n";

    DIDDocument noMethodDoc(holderDID);
    DIDResolver noMethodResolver;
    noMethodResolver.registerDocument(noMethodDoc);
    assert(!verifier.verifyHolderControl(
        vc, proof, holderDID.getValue(), session, noMethodResolver, zkp));
    std::cout << "[PASS] Schnorr verification method missing\n";

    DID otherDID("did:example:other001");
    assert(!verifier.verifyHolderControl(
        vc, proof, otherDID.getValue(), session, resolver, zkp));
    std::cout << "[PASS] Subject / claimed DID mismatch\n";

    DIDDocument badHolderDoc(holderDID);
    badHolderDoc.addVerificationMethod(VerificationMethod(
        holder.getSchnorrMethodId(),
        "SchnorrVerificationKey",
        holderDID.toString(),
        "3"));
    DIDResolver badResolver;
    badResolver.registerDocument(badHolderDoc);
    assert(!verifier.verifyHolderControl(
        vc, proof, holderDID.getValue(), session, badResolver, zkp));
    std::cout << "[PASS] Wrong public value\n";

    bool wrongSessionRejected = false;
    const std::string otherSessions[] = {
        "nonce-session-002",
        "nonce-session-003",
        "other-challenge-xyz",
        "completely-different-nonce"};
    for (const auto& other : otherSessions)
    {
        if (!verifier.verifyHolderControl(
                vc, proof, holderDID.getValue(), other, resolver, zkp))
        {
            wrongSessionRejected = true;
            break;
        }
    }
    assert(wrongSessionRejected);
    std::cout << "[PASS] Wrong session challenge\n\n";
}

int main()
{
    std::cout << "===== TEST ACTORS MODULE =====\n\n";

    testHolder();
    testIssuer();
    testVerifier();
    testVerifierZKP();
    testHolderDidControl();

    std::cout << "===== ALL ACTORS TESTS PASSED =====\n";
    return 0;
}
