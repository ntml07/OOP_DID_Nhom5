#pragma once
#include <map>
#include <string>
#include "identity/DID.h"

class CredentialSubject {
private:
    DID did;
    std::map<std::string, std::string> claims;
public:
    CredentialSubject(const DID& did);
    const DID& getDID() const;
    void addClaim(const std::string& key, const std::string& value);
    bool hasClaim(const std::string& key) const;
    std::string getClaim(const std::string& key) const;
    const std::map<std::string, std::string>& getClaims() const;
    std::string serialize() const;
};
