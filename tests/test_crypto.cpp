#include <bits/stdc++.h>
#include "crypto/DigitalSignature.h"
#include "crypto/RSA.h"

void testDigitalSignature() {
    std::cout << "[TEST] Running DigitalSignature tests...\n";

    DigitalSignature emptySig;
    assert(emptySig.empty() == true);

    DigitalSignature sig("SHA256withRSA", "key-01", "sig_value_test");
    assert(sig.getAlgorithm() == "SHA256withRSA");
    assert(sig.getKeyId() == "key-01");
    assert(sig.getValue() == "sig_value_test");
    assert(sig.empty() == false);

    std::cout << "[PASS] DigitalSignature tests passed!\n";
}

void testRSA() {
    std::cout << "[TEST] Running RSA tests...\n";

    RSA rsa;
    rsa.generateKeyPair();
    std::string pubKey = rsa.getPublicKey();

    std::string data = "Decentralized Identity Data";
    std::string keyId = "key-rsa-xyz";

    DigitalSignature sig = rsa.sign(data, keyId);

    assert(rsa.verify(data, sig, pubKey) == true);

    std::string tamperedData = "Tampered Data";
    assert(rsa.verify(tamperedData, sig, pubKey) == false);

    std::string wrongPubKey = "INVALID_PUBLIC_KEY";
    assert(rsa.verify(data, sig, wrongPubKey) == false);

    assert(rsa.getAlgorithmName() == "SHA256withRSA");

    std::cout << "[PASS] RSA tests passed!\n";
}

int main() {
    testDigitalSignature();
    testRSA();
    std::cout << "[ALL TESTS PASSED SUCCESSFULLY!]\n";
    return 0;
}