#include <iostream>
#include <cassert>

#include "identity/DID.h"
#include "identity/VerificationMethod.h"
#include "identity/DIDDocument.h"
#include "identity/DIDResolver.h"

void testDID()
{
    std::cout << "Test 1: DID\n";

    DID issuerDID("did:example:issuer001");

    assert(issuerDID.getValue() == "did:example:issuer001");
    assert(issuerDID.toString() == "did:example:issuer001");
    assert(issuerDID.isValid() == true);
    assert(issuerDID == DID("did:example:issuer001"));
    assert(!(issuerDID == DID("did:example:holder001")));
    assert(DID("issuer001").isValid() == false);

    std::cout << "DID: " << issuerDID.getValue() << "\n";
    std::cout << "DID test: PASSED\n\n";
}

void testVerificationMethod()
{
    std::cout << "Test 2: VerificationMethod\n";

    VerificationMethod verificationMethod(
        "did:example:issuer001#key-1",
        "RSA",
        "did:example:issuer001",
        "PUBLIC_KEY_123");

    assert(verificationMethod.getId() == "did:example:issuer001#key-1");
    assert(verificationMethod.getType() == "RSA");
    assert(verificationMethod.getController() == "did:example:issuer001");
    assert(verificationMethod.getPublicKey() == "PUBLIC_KEY_123");

    std::cout << "Key ID: " << verificationMethod.getId() << "\n";
    std::cout << "Public Key: " << verificationMethod.getPublicKey() << "\n";
    std::cout << "VerificationMethod test: PASSED\n\n";
}

void testDIDDocument()
{
    std::cout << "Test 3: DIDDocument\n";

    DID issuerDID("did:example:issuer001");
    VerificationMethod verificationMethod(
        "did:example:issuer001#key-1",
        "RSA",
        "did:example:issuer001",
        "PUBLIC_KEY_123");

    DIDDocument document(issuerDID);
    document.addVerificationMethod(verificationMethod);

    assert(document.getDID().getValue() == "did:example:issuer001");
    assert(document.getVerificationMethods().size() == 1);

    const VerificationMethod* foundMethod =
        document.findVerificationMethod("did:example:issuer001#key-1");
    assert(foundMethod != nullptr);
    assert(foundMethod->getPublicKey() == "PUBLIC_KEY_123");

    std::cout << "Found Public Key: " << foundMethod->getPublicKey() << "\n";

    const VerificationMethod* notFoundMethod =
        document.findVerificationMethod("did:example:issuer001#key-999");
    assert(notFoundMethod == nullptr);

    std::cout << "Unknown keyId returns nullptr: PASSED\n";
    std::cout << "DIDDocument test: PASSED\n\n";
}

void testDIDResolver()
{
    std::cout << "Test 4: DIDResolver\n";

    DID issuerDID("did:example:issuer001");
    VerificationMethod verificationMethod(
        "did:example:issuer001#key-1",
        "RSA",
        "did:example:issuer001",
        "PUBLIC_KEY_123");
    DIDDocument document(issuerDID);
    document.addVerificationMethod(verificationMethod);

    DIDResolver resolver;
    resolver.registerDocument(document);

    const DIDDocument* resolvedDocument = resolver.resolve("did:example:issuer001");
    assert(resolvedDocument != nullptr);
    assert(resolvedDocument->getDID().getValue() == "did:example:issuer001");
    assert(resolver.exists("did:example:issuer001") == true);

    const DIDDocument* unknownDocument = resolver.resolve("did:example:not-exist");
    assert(unknownDocument == nullptr);
    assert(resolver.exists("did:example:not-exist") == false);

    std::cout << "Resolve existing DID: PASSED\n";
    std::cout << "Unknown DID returns nullptr: PASSED\n\n";
}

void testFullIdentityFlow()
{
    std::cout << "Test 5: Full Identity Flow\n";

    DID issuerDID("did:example:issuer001");
    VerificationMethod verificationMethod(
        "did:example:issuer001#key-1",
        "RSA",
        "did:example:issuer001",
        "PUBLIC_KEY_123");
    DIDDocument document(issuerDID);
    document.addVerificationMethod(verificationMethod);

    DIDResolver resolver;
    resolver.registerDocument(document);

    const DIDDocument* resolved = resolver.resolve("did:example:issuer001");
    assert(resolved != nullptr);

    const VerificationMethod* key =
        resolved->findVerificationMethod("did:example:issuer001#key-1");
    assert(key != nullptr);
    assert(key->getPublicKey() == "PUBLIC_KEY_123");

    std::cout << "DID\n";
    std::cout << "  -> DIDResolver\n";
    std::cout << "  -> DIDDocument\n";
    std::cout << "  -> VerificationMethod\n";
    std::cout << "  -> Public Key: " << key->getPublicKey() << "\n";
    std::cout << "Full Identity Flow: PASSED\n\n";
}

int main()
{
    std::cout << "===== TEST IDENTITY MODULE =====\n\n";

    testDID();
    testVerificationMethod();
    testDIDDocument();
    testDIDResolver();
    testFullIdentityFlow();

    std::cout << "===== ALL IDENTITY TESTS PASSED =====\n";
    return 0;
}
