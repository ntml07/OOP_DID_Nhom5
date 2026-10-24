#include "credential/CredentialStatus.h"


CredentialStatus::CredentialStatus() : state(CredentialState::VALID) {}

CredentialState CredentialStatus::getState() const 
{
    return state;
}

bool CredentialStatus::isValid() const 
{
    return state == CredentialState::VALID;
}

void CredentialStatus::activate() 
{
    state = CredentialState::VALID;
}

void CredentialStatus::suspend() 
{
    state = CredentialState::SUSPENDED;
}

void CredentialStatus::revoke() 
{
    state = CredentialState::REVOKED;
}

std::string CredentialStatus::toString() const 
{
    switch (state) 
    {
    case CredentialState::VALID:
        return "VALID";
    case CredentialState::SUSPENDED:
        return "SUSPENDED";
    case CredentialState::REVOKED:
        return "REVOKED";
    default:
        return "UNKNOWN";
    }
}
