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

void testValidFullFlow()
{
    // Main block: RSA VC verify, then separate Schnorr DID-control
    std::cout << "Test 1: full valid flow\n";

    RSA crypto;
    crypto.generateKeyPair();
    SchnorrZKP zkp;

    DID issuerDID("did:example:issuer001");
    const std::string keyId = "did:example:issuer001#key-1";
    Issuer issuer(issuerDID, crypto, keyId);

    DIDResolver resolver;

    DIDDocument document(issuerDID);
    document.addVerificationMethod(VerificationMethod(
        keyId,
        "RsaVerificationKey",
        issuerDID.toString(),
        issuer.getPublicKey()));
    resolver.registerDocument(document);

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
    subject.addClaim("name", "Nguyen Van A");
    subject.addClaim("membership", "active");

    VerifiableCredential vc = issuer.issueCredential(
        "vc:001",
        subject,
        "2024-01-01");

    holder.receiveCredential(vc);

    assert(holder.findCredential("vc:001") != nullptr);
    assert(vc.hasSignature() == true);

    Verifier verifier(DID("did:example:verifier001"));

    assert(verifier.verifyCredential(vc, resolver, crypto, issuer) == true);

    const std::string session = "integration-session-1";
    ZKPProofData proof = holder.createOwnershipProof(zkp, session);
    assert(verifier.verifyHolderControl(
        vc, proof, holderDID.getValue(), session, resolver, zkp));

    std::cout << "Full valid flow: PASSED\n\n";
}

void testInvalidCases()
{
    std::cout << "Test 2: invalid verification cases\n";

    RSA crypto;
    crypto.generateKeyPair();

    DID issuerDID("did:example:issuer001");
    const std::string keyId = "did:example:issuer001#key-1";
    Issuer issuer(issuerDID, crypto, keyId);

    DIDDocument document(issuerDID);
    document.addVerificationMethod(VerificationMethod(
        keyId,
        "RsaVerificationKey",
        issuerDID.toString(),
        issuer.getPublicKey()));

    DIDResolver resolver;
    resolver.registerDocument(document);

    DID holderDID("did:example:holder001");
    CredentialSubject subject(holderDID);
    subject.addClaim("name", "Nguyen Van A");

    VerifiableCredential vc = issuer.issueCredential(
        "vc:001",
        subject,
        "2024-01-01");

    Verifier verifier(DID("did:example:verifier001"));

    assert(issuer.revokeCredential(vc.getId()) == true);
    assert(vc.getStatus().isValid() == true);
    assert(verifier.verifyCredential(vc, resolver, crypto, issuer) == false);

    assert(issuer.revokeCredential("vc:never-issued") == false);
    assert(issuer.revokeCredential(vc.getId()) == false);

    VerifiableCredential otherVc = issuer.issueCredential(
        "vc:001-other",
        subject,
        "2024-01-01");
    assert(verifier.verifyCredential(otherVc, resolver, crypto, issuer) == true);

    VerifiableCredential suspendedVC = otherVc;
    suspendedVC.suspend();
    assert(verifier.verifyCredential(suspendedVC, resolver, crypto, issuer) == false);

    VerifiableCredential unknownIssuerVC(
        "vc:002",
        "did:example:unknown001",
        subject,
        "2024-01-01");
    unknownIssuerVC.setSignature(otherVc.getSignature());
    assert(verifier.verifyCredential(unknownIssuerVC, resolver, crypto, issuer) == false);

    Issuer wrongIssuer(issuerDID, crypto, "did:example:issuer001#missing-key");
    VerifiableCredential wrongKeyVC = wrongIssuer.issueCredential(
        "vc:003",
        subject,
        "2024-01-01");
    assert(verifier.verifyCredential(wrongKeyVC, resolver, crypto, wrongIssuer) == false);

    CredentialSubject changedSubject(holderDID);
    changedSubject.addClaim("name", "Nguyen Thi B");
    VerifiableCredential changedVC(
        otherVc.getId(),
        otherVc.getIssuerDID(),
        changedSubject,
        otherVc.getIssuanceDate(),
        otherVc.getType());
    changedVC.setSignature(otherVc.getSignature());
    assert(verifier.verifyCredential(changedVC, resolver, crypto, issuer) == false);

    DIDDocument wrongDocument(issuerDID);
    wrongDocument.addVerificationMethod(VerificationMethod(
        keyId,
        "RsaVerificationKey",
        issuerDID.toString(),
        "WRONG_PUBLIC_KEY"));
    DIDResolver wrongResolver;
    wrongResolver.registerDocument(wrongDocument);
    assert(verifier.verifyCredential(otherVc, wrongResolver, crypto, issuer) == false);

    std::cout << "Invalid cases: PASSED\n\n";
}

int main()
{
    std::cout << "===== TEST INTEGRATION =====\n\n";

    testValidFullFlow();
    testInvalidCases();

    std::cout << "===== ALL INTEGRATION TESTS PASSED =====\n";
    return 0;
}
