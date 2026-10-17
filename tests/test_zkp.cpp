#include <iostream>
#include <cassert>
#include <string>

#include "zkp/SchnorrZKP.h"

void testValidProof()
{
    std::cout << "Test 1: secret -> publicValue -> proof -> verify\n";

    SchnorrZKP zkp;
    const long long secret = 7;
    const std::string statement = "User is over 18";

    const long long publicValue = zkp.createPublicValue(secret);
    const ZKPProofData proof = zkp.generateProof(secret, statement);

    assert(zkp.verifyProof(proof, publicValue, statement) == true);

    std::cout << "Valid proof: PASSED\n\n";
}

void testModifiedProof()
{
    std::cout << "Test 2: sua proof / statement -> INVALID\n";

    SchnorrZKP zkp;
    const long long secret = 7;
    const std::string statement = "User is over 18";
    const long long publicValue = zkp.createPublicValue(secret);
    const ZKPProofData proof = zkp.generateProof(secret, statement);

    ZKPProofData changedProof = proof;
    changedProof.response = (changedProof.response + 1) % 11;
    assert(zkp.verifyProof(changedProof, publicValue, statement) == false);

    const std::string candidates[] = {
        "User is under 18",
        "User is over 21",
        "Different statement A",
        "Different statement B"};
    bool rejectedChangedStatement = false;
    for (const auto& changedStatement : candidates) {
        if (!zkp.verifyProof(proof, publicValue, changedStatement)) {
            rejectedChangedStatement = true;
            break;
        }
    }
    assert(rejectedChangedStatement == true);

    std::cout << "Modified proof: PASSED\n\n";
}

void testWrongPublicValue()
{
    std::cout << "Test 3: sai publicValue -> INVALID\n";

    SchnorrZKP zkp;
    const long long secret = 7;
    const std::string statement = "User is over 18";
    const long long publicValue = zkp.createPublicValue(secret);
    const ZKPProofData proof = zkp.generateProof(secret, statement);

    const long long wrongPublicValue = zkp.createPublicValue(secret + 1);
    assert(wrongPublicValue != publicValue);
    assert(zkp.verifyProof(proof, wrongPublicValue, statement) == false);

    std::cout << "Wrong public value: PASSED\n\n";
}

int main()
{
    std::cout << "===== TEST ZKP MODULE =====\n\n";

    testValidProof();
    testModifiedProof();
    testWrongPublicValue();

    std::cout << "===== ALL ZKP TESTS PASSED =====\n";
    return 0;
}
