#pragma once
#include <string>

enum class CredentialState { VALID, SUSPENDED, REVOKED };

class CredentialStatus {
private:
    CredentialState state;
public:
    CredentialStatus();
    CredentialState getState() const;
    bool isValid() const;
    void activate();
    void suspend();
    void revoke();
    std::string toString() const;
};
