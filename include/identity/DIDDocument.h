#pragma once
#include <string>
#include <vector>
#include "identity/DID.h"
#include "identity/VerificationMethod.h"

class DIDDocument {
private:
    DID did;
    std::vector<VerificationMethod> verificationMethods;
public:
    DIDDocument(const DID& did);
    const DID& getDID() const;
    void addVerificationMethod(const VerificationMethod& method);
    const std::vector<VerificationMethod>& getVerificationMethods() const;
    const VerificationMethod* findVerificationMethod(const std::string& methodId) const;
    std::string serialize() const;
};
