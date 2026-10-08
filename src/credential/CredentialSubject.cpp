#include "credential/CredentialSubject.h"

// TODO: Implement methods declared in CredentialSubject.h

CredentialSubject::CredentialSubject(const DID& did) : did(did) {}

const DID& CredentialSubject::getDID() const 
{
    return did;
}

void CredentialSubject::addClaim(const std::string& key, const std::string& value) 
{
    claims[key] = value;
}

bool CredentialSubject::hasClaim(const std::string& key) const 
{
    return claims.find(key) != claims.end();
}

std::string CredentialSubject::getClaim(const std::string& key) const 
{
    auto it = claims.find(key);
    if (it != claims.end()) {
        return it->second;
    }
    return "";
}

const std::map<std::string, std::string>& CredentialSubject::getClaims() const 
{
    return claims;
}

std::string CredentialSubject::serialize() const 
{
    std::ostringstream oss;
    oss << "Subject DID: " << did.toString() << "\n";
    for (const auto& pair : claims) 
    {
        oss << "Claim [" << pair.first << "]: " << pair.second << "\n";
    }
    return oss.str();
}
