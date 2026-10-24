#include "credential/VerifiableCredential.h"
#include <iostream>
#include <sstream>

VerifiableCredential::VerifiableCredential(
    const std::string& id,
    const std::string& issuerDID,
    const CredentialSubject& subject,
    const std::string& issuanceDate,
    const std::string& type)
    : id(id),
    issuerDID(issuerDID),
    subject(subject),
    issuanceDate(issuanceDate),
    type(type)
{
    this->context = "https://www.w3.org/2018/credentials/v1";
    // status mặc định sẽ được khởi tạo là VALID nhờ constructor của CredentialStatus
}

std::string VerifiableCredential::getId() const 
{
    return id;
}

std::string VerifiableCredential::getIssuerDID() const 
{
    return issuerDID;
}

const CredentialSubject& VerifiableCredential::getSubject() const 
{
    return subject;
}

const CredentialStatus& VerifiableCredential::getStatus() const 
{
    return status;
}

const DigitalSignature& VerifiableCredential::getSignature() const 
{
    return signature;
}

std::string VerifiableCredential::getType() const 
{
    return type;
}

std::string VerifiableCredential::getIssuanceDate() const 
{
    return issuanceDate;
}

void VerifiableCredential::setSignature(const DigitalSignature& sig) 
{
    signature = sig;
}

bool VerifiableCredential::hasSignature() const 
{
    return !signature.empty();
}

std::string VerifiableCredential::serializeForSigning() const 
{
    std::ostringstream oss;
    oss << "Context: " << context << "\n";
    oss << "ID: " << id << "\n";
    oss << "Type: " << type << "\n";
    oss << "Issuer: " << issuerDID << "\n";
    oss << "Issuance Date: " << issuanceDate << "\n";
    oss << subject.serialize();
    oss << "Status: " << status.toString() << "\n";

    return oss.str();
}

void VerifiableCredential::activate() 
{
    status.activate();
}

void VerifiableCredential::suspend() 
{
    status.suspend();
}

void VerifiableCredential::revoke() 
{
    status.revoke();
}

void VerifiableCredential::display() const 
{
    std::cout << "VERIFIABLE CREDENTIAL \n";
    std::cout << "Context: " << context << "\n";
    std::cout << "ID: " << id << "\n";
    std::cout << "Type: " << type << "\n";
    std::cout << "Issuer: " << issuerDID << "\n";
    std::cout << "Issuance Date: " << issuanceDate << "\n";
    std::cout << subject.serialize();
    std::cout << "Status: " << status.toString() << "\n";

    if (hasSignature()) 
    {
        std::cout << "Signature Algorithm: " << signature.getAlgorithm() << "\n";
        std::cout << "Signature KeyID: " << signature.getKeyId() << "\n";
        std::cout << "Signature Value: " << signature.getValue() << "\n";
    }
    else 
    {
        std::cout << "Signature: <EMPTY>";
    }
}
