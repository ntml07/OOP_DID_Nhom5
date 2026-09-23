#pragma once
#include <string>

struct ZKPProofData {
    long long commitment;
    long long challenge;
    long long response;
};

class IZKP {
public:
    virtual ~IZKP() = default;
    virtual long long createPublicValue(long long secret) const = 0;
    virtual ZKPProofData generateProof(long long secret, const std::string& statement) const = 0;
    virtual bool verifyProof(const ZKPProofData& proof, long long publicValue, const std::string& statement) const = 0;
};
