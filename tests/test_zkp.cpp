#include "zkp/SchnorrZKP.h"

#include <iostream>
#include <string>

namespace {
int failures = 0;

void check(bool condition, const std::string& name)
{
    std::cout << (condition ? "[PASS] " : "[FAIL] ") << name << '\n';
    if (!condition) ++failures;
}
}

int main()
{
    SchnorrZKP zkp;
    constexpr long long secret = 7;
    const std::string statement = "User is over 18";

    // Full flow: secret -> public value -> proof -> verify.
    const long long publicValue = zkp.createPublicValue(secret);
    const ZKPProofData proof = zkp.generateProof(secret, statement);
    check(zkp.verifyProof(proof, publicValue, statement),
          "Valid proof verifies (secret -> publicValue -> proof -> verify)");

    // Change the response, preserving its valid numeric range.
    ZKPProofData changedProof = proof;
    changedProof.response = (changedProof.response + 1) % 11;
    check(!zkp.verifyProof(changedProof, publicValue, statement),
          "Modified proof is rejected");

    // Pick a changed statement with a different challenge for this commitment.
    // With the intentionally tiny demo group, challenge collisions are possible.
    const std::string candidates[] = {
        "User is under 18", "User is over 21", "User is under 21",
        "User passed identity check", "User did not pass identity check",
        "Different statement A", "Different statement B", "Different statement C"
    };
    bool rejectedChangedStatement = false;
    for (const auto& changedStatement : candidates) {
        if (changedStatement != statement &&
            !zkp.verifyProof(proof, publicValue, changedStatement)) {
            rejectedChangedStatement = true;
            break;
        }
    }
    check(rejectedChangedStatement, "Changed statement is rejected");

    // Use a different secret's public value (not merely an out-of-range value).
    const long long wrongPublicValue = zkp.createPublicValue(secret + 1);
    check(wrongPublicValue != publicValue &&
              !zkp.verifyProof(proof, wrongPublicValue, statement),
          "Wrong public value is rejected");

    if (failures != 0) {
        std::cout << failures << " test(s) failed.\n";
        return 1;
    }
    std::cout << "All SchnorrZKP tests passed.\n";
    return 0;
}
