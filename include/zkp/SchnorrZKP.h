#pragma once
#include "zkp/IZKP.h"

class SchnorrZKP : public IZKP {
public:
    long long createPublicValue(long long secret) const override;
    ZKPProofData generateProof(long long secret, const std::string& statement) const override;
    bool verifyProof(const ZKPProofData& proof, long long publicValue, const std::string& statement) const override;
};
