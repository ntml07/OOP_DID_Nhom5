#include <iostream>
#include <cassert>
#include <string>

#include "crypto/DigitalSignature.h"
#include "crypto/RSA.h"

void testDigitalSignature()
{
    // Main block: DigitalSignature empty vs filled data object
    std::cout << "Test 1: DigitalSignature\n";

    DigitalSignature emptySig;
    assert(emptySig.empty() == true);

    DigitalSignature sig("RSA-Educational", "key-01", "sig_value_test");
    assert(sig.getAlgorithm() == "RSA-Educational");
    assert(sig.getKeyId() == "key-01");
    assert(sig.getValue() == "sig_value_test");
    assert(sig.empty() == false);

    std::cout << "DigitalSignature: PASSED\n\n";
}

void testRSA()
{
    // Main block: educational RSA sign / verify (chosen test vectors)
    std::cout << "Test 2: RSA sign + verify\n";

    RSA rsa;
    rsa.generateKeyPair();
    std::string pubKey = rsa.getPublicKey();
    assert(pubKey.empty() == false);
    assert(pubKey.find('|') != std::string::npos);

    std::string data = "Decentralized Identity Data";
    std::string keyId = "did:example:issuer001#key-1";

    DigitalSignature sig = rsa.sign(data, keyId);
    assert(sig.empty() == false);
    assert(sig.getKeyId() == keyId);
    assert(sig.getAlgorithm() == "RSA-Educational");
    assert(rsa.getAlgorithmName() == "RSA-Educational");

    assert(rsa.verify(data, sig, pubKey) == true);

    // Tamper check for this fixed string only (messageToNumber can collide in theory)
    assert(rsa.verify("Tampered Data", sig, pubKey) == false);

    assert(rsa.verify(data, sig, "INVALID_PUBLIC_KEY") == false);

    // Other key pair's public key must not verify this signature
    RSA other;
    other.generateKeyPair();
    std::string otherPub = other.getPublicKey();
    if (otherPub != pubKey) {
        assert(rsa.verify(data, sig, otherPub) == false);
    }

    DigitalSignature emptySig;
    assert(rsa.verify(data, emptySig, pubKey) == false);

    DigitalSignature wrongAlgo("SHA256withRSA", keyId, sig.getValue());
    assert(rsa.verify(data, wrongAlgo, pubKey) == false);

    DigitalSignature badValue("RSA-Educational", keyId, "not-a-number");
    assert(rsa.verify(data, badValue, pubKey) == false);

    std::cout << "RSA: PASSED\n\n";
}

int main()
{
    std::cout << "===== TEST CRYPTO MODULE =====\n\n";

    testDigitalSignature();
    testRSA();

    std::cout << "===== ALL CRYPTO TESTS PASSED =====\n";
    return 0;
}
