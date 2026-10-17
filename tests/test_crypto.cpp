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

    DigitalSignature sig("SHA256withRSA", "key-01", "sig_value_test");
    assert(sig.getAlgorithm() == "SHA256withRSA");
    assert(sig.getKeyId() == "key-01");
    assert(sig.getValue() == "sig_value_test");
    assert(sig.empty() == false);

    std::cout << "DigitalSignature: PASSED\n\n";
}

void testRSA()
{
    // Main block: RSA sign then verify valid / tampered / wrong key
    std::cout << "Test 2: RSA sign + verify\n";

    RSA rsa;
    rsa.generateKeyPair();
    std::string pubKey = rsa.getPublicKey();

    std::string data = "Decentralized Identity Data";
    std::string keyId = "did:example:issuer001#key-1";

    DigitalSignature sig = rsa.sign(data, keyId);
    assert(sig.empty() == false);
    assert(sig.getKeyId() == keyId);
    assert(rsa.getAlgorithmName() == "SHA256withRSA");

    assert(rsa.verify(data, sig, pubKey) == true);
    assert(rsa.verify("Tampered Data", sig, pubKey) == false);
    assert(rsa.verify(data, sig, "INVALID_PUBLIC_KEY") == false);

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
