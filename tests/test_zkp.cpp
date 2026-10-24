#include <iostream>
#include <cassert>
#include <string>

#include "zkp/SchnorrZKP.h"

const long long secret = 7;
const std::string holderDid = "did:example:holder001";
const std::string sessionChallenge = "session-demo-001";

std::string makeStatement(
    const std::string& sessionChallenge,
    const std::string& holderDid)
{
    return sessionChallenge + "|control:" + holderDid;
}

void testValidProof()
{
    std::cout << "Test 1: Tao va xac minh proof hop le\n";

    SchnorrZKP zkp;

    const std::string statement =
        makeStatement(sessionChallenge, holderDid);

    const long long publicValue = zkp.createPublicValue(secret);

    const ZKPProofData proof =
        zkp.generateProof(secret, statement);

    assert(zkp.verifyProof(proof, publicValue, statement) == true);

    std::cout << "Valid proof: PASSED\n\n";
}

void testModifiedProof()
{
    std::cout << "Test 2: Thay doi proof / statement -> INVALID\n";

    SchnorrZKP zkp;

    const std::string statement =
        makeStatement(sessionChallenge, holderDid);

    const long long publicValue = zkp.createPublicValue(secret);

    const ZKPProofData proof =
        zkp.generateProof(secret, statement);

    ZKPProofData changedProof = proof;
    changedProof.response = (changedProof.response + 1) % 11;

    assert(zkp.verifyProof(changedProof, publicValue, statement) == false);

    bool rejectedChangedStatement = false;

    for (int i = 1; i <= 100; ++i)
    {
        const std::string changedStatement =
            makeStatement(
                sessionChallenge + "-changed-" + std::to_string(i),
                holderDid);

        if (!zkp.verifyProof(proof, publicValue, changedStatement))
        {
            rejectedChangedStatement = true;
            break;
        }
    }

    assert(rejectedChangedStatement == true);

    std::cout << "Modified proof / statement: PASSED\n\n";
}

void testWrongPublicValue()
{
    std::cout << "Test 3: Public value khong hop le -> INVALID\n";

    SchnorrZKP zkp;

    const std::string statement =
        makeStatement(sessionChallenge, holderDid);

    const ZKPProofData proof =
        zkp.generateProof(secret, statement);

    assert(zkp.verifyProof(proof, 0, statement) == false);

    std::cout << "Invalid public value: PASSED\n\n";
}

int main()
{
    std::cout << "===== TEST SCHNORR ZKP MODULE =====\n\n";

    testValidProof();
    testModifiedProof();
    testWrongPublicValue();

    std::cout << "===== ALL ZKP TESTS PASSED =====\n";

    return 0;
}
