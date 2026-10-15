#include "credential/VerifiableCredential.h"
#include "credential/CredentialSubject.h"
#include "credential/CredentialStatus.h"
#include "crypto/DigitalSignature.h"
#include "identity/DID.h"

#include <iostream>
#include <string>

// TODO: Add tests for this module.

static int g_passed = 0;
static int g_failed = 0;

static void check(bool condition, const std::string& name) 
{
    if (condition) 
    {
        std::cout << "  [PASS] " << name << "\n";
        ++g_passed;
    }
    else 
    {
        std::cout << "  [FAIL] " << name << "\n";
        ++g_failed;
    }
}

static void printSection(const std::string& title) 
{
    std::cout << "\n " << title << " \n";
}

void testCredentialSubject() 
{
    printSection("CredentialSubject");

    DID holderDID("did:example:holder001");
    CredentialSubject subject(holderDID);

    check(subject.getDID().getValue() == "did:example:holder001",
        "getDID().getValue() tra ve dung DID");

    check(subject.hasClaim("name") == false,
        "hasClaim('name') = false khi chua them");
    check(subject.getClaim("name") == "",
        "getClaim('name') = '' khi chua them");

    subject.addClaim("name", "Alice");
    subject.addClaim("membership", "active");
    subject.addClaim("qualification", "ABC");

    check(subject.hasClaim("name") == true,
        "hasClaim('name') = true sau addClaim");
    check(subject.getClaim("name") == "Alice",
        "getClaim('name') tra dung 'Alice'");
    check(subject.getClaim("membership") == "active",
        "getClaim('membership') tra dung");
    check(subject.getClaim("qualification") == "ABC",
        "getClaim('qualification') tra dung");

    const auto& claims = subject.getClaims();
    check(claims.size() == 3,
        "getClaims().size() = 3 sau khi them 3 claim");

    subject.addClaim("name", "Bob");
    check(subject.getClaim("name") == "Bob",
        "addClaim ghi de gia tri cu khi trung key");
    check(subject.getClaims().size() == 3,
        "size khong tang khi ghi de");

    std::string s1 = subject.serialize();
    std::string s2 = subject.serialize();
    check(s1 == s2,
        "serialize() on dinh giua 2 lan goi");
    check(s1.find("Bob") != std::string::npos,
        "serialize() chua gia tri moi 'Bob'");
    check(s1.find("Alice") == std::string::npos,
        "serialize() khong con gia tri cu 'Alice'");
    check(s1.find("membership") != std::string::npos &&
        s1.find("qualification") != std::string::npos,
        "serialize() chua day du cac claim");

    CredentialSubject s3(holderDID);
    s3.addClaim("zebra", "1");
    s3.addClaim("apple", "2");
    s3.addClaim("mango", "3");
    std::string ordered = s3.serialize();
    size_t posApple = ordered.find("apple");
    size_t posMango = ordered.find("mango");
    size_t posZebra = ordered.find("zebra");
    check(posApple < posMango && posMango < posZebra,
        "serialize() sap xep claim theo alphabet (on dinh)");
}

void testCredentialStatus() 
{
    printSection("CredentialStatus");

    CredentialStatus status;

    check(status.getState() == CredentialState::VALID,
        "state mac dinh la VALID");
    check(status.isValid() == true,
        "isValid() = true khi mac dinh");
    check(status.toString() == "VALID",
        "toString() = 'VALID' khi mac dinh");

    status.suspend();
    check(status.getState() == CredentialState::SUSPENDED,
        "state = SUSPENDED sau suspend()");
    check(status.isValid() == false,
        "isValid() = false khi SUSPENDED");
    check(status.toString() == "SUSPENDED",
        "toString() = 'SUSPENDED'");

    status.revoke();
    check(status.getState() == CredentialState::REVOKED,
        "state = REVOKED sau revoke()");
    check(status.isValid() == false,
        "isValid() = false khi REVOKED");
    check(status.toString() == "REVOKED",
        "toString() = 'REVOKED'");

    status.activate();
    check(status.getState() == CredentialState::VALID,
        "state = VALID sau activate()");
    check(status.isValid() == true,
        "isValid() = true sau activate()");
    check(status.toString() == "VALID",
        "toString() = 'VALID' sau activate()");
}

void testDigitalSignature() 
{
    printSection("DigitalSignature");

    DigitalSignature emptySig;
    check(emptySig.empty() == true, "empty() = true voi default");
    check(emptySig.getAlgorithm() == "", "algorithm mac dinh rong");
    check(emptySig.getKeyId() == "", "keyId mac dinh rong");
    check(emptySig.getValue() == "", "value mac dinh rong");

    DigitalSignature sig("RSA-SHA256", "did:example:issuer001#key1", "abcdef123456");
    check(sig.empty() == false, "empty() = false sau khi gan");
    check(sig.getAlgorithm() == "RSA-SHA256", "getAlgorithm dung");
    check(sig.getKeyId() == "did:example:issuer001#key1", "getKeyId dung");
    check(sig.getValue() == "abcdef123456", "getValue dung");
}

void testVerifiableCredential() 
{
    printSection("VerifiableCredential - Khoi tao va thong tin co ban");

    DID holderDID("did:example:holder001");
    CredentialSubject subject(holderDID);
    subject.addClaim("name", "Alice");
    subject.addClaim("membership", "active");

    VerifiableCredential vc(
        "vc:001",
        "did:example:issuer001",
        subject,
        "2024-01-01T00:00:00Z"
    );

    check(vc.getId() == "vc:001", "getId dung");
    check(vc.getIssuerDID() == "did:example:issuer001", "getIssuerDID dung");
    check(vc.getIssuanceDate() == "2024-01-01T00:00:00Z", "getIssuanceDate dung");
    check(vc.getType() == "VerifiableCredential", "getType mac dinh = 'VerifiableCredential'");

    check(vc.getSubject().getDID().getValue() == "did:example:holder001",
        "subject DID dung");
    check(vc.getSubject().getClaim("name") == "Alice",
        "subject claim dung");
    check(vc.getSubject().getClaim("membership") == "active",
        "subject claim membership dung");

    check(vc.getStatus().isValid() == true,
        "status mac dinh VALID");
    check(vc.getStatus().toString() == "VALID",
        "status toString = 'VALID'");

    check(vc.hasSignature() == false,
        "hasSignature() = false khi chua ky");

    printSection("VerifiableCredential - serializeForSigning");

    std::string payload1 = vc.serializeForSigning();
    std::string payload2 = vc.serializeForSigning();

    check(payload1 == payload2,
        "serializeForSigning() on dinh giua 2 lan goi");
    check(payload1.find("did:example:issuer001") != std::string::npos,
        "payload chua issuer DID");
    check(payload1.find("vc:001") != std::string::npos,
        "payload chua VC id");
    check(payload1.find("did:example:holder001") != std::string::npos,
        "payload chua subject DID");
    check(payload1.find("Alice") != std::string::npos,
        "payload chua claim 'Alice'");

    printSection("VerifiableCredential - setSignature va hasSignature");

    DigitalSignature ds("RSA-SHA256",
        "did:example:issuer001#key1",
        "SIGNATURE_VALUE_XYZ");
    vc.setSignature(ds);

    check(vc.hasSignature() == true,
        "hasSignature() = true sau setSignature");
    check(vc.getSignature().getAlgorithm() == "RSA-SHA256",
        "signature algorithm dung");
    check(vc.getSignature().getKeyId() == "did:example:issuer001#key1",
        "signature keyId dung");
    check(vc.getSignature().getValue() == "SIGNATURE_VALUE_XYZ",
        "signature value dung");

    std::string payload3 = vc.serializeForSigning();
    check(payload3 == payload1,
        "serializeForSigning KHONG doi sau khi setSignature");
    check(payload3.find("SIGNATURE_VALUE_XYZ") == std::string::npos,
        "payload KHONG chua gia tri chu ky");
    check(payload3.find("RSA-SHA256") == std::string::npos,
        "payload KHONG chua algorithm cua chu ky");

    printSection("VerifiableCredential - suspend / revoke / activate");

    vc.suspend();
    check(vc.getStatus().isValid() == false,
        "isValid() = false sau suspend()");
    check(vc.getStatus().toString() == "SUSPENDED",
        "status = SUSPENDED sau suspend()");

    vc.revoke();
    check(vc.getStatus().isValid() == false,
        "isValid() = false sau revoke()");
    check(vc.getStatus().toString() == "REVOKED",
        "status = REVOKED sau revoke()");

    vc.activate();
    check(vc.getStatus().isValid() == true,
        "isValid() = true sau activate()");
    check(vc.getStatus().toString() == "VALID",
        "status = VALID sau activate()");

    printSection("VerifiableCredential - Subject duoc copy theo gia tri");

    DID h2("did:example:holder999");
    CredentialSubject sub2(h2);
    sub2.addClaim("role", "user");

    VerifiableCredential vc2("vc:002",
        "did:example:issuer001",
        sub2,
        "2024-01-02T00:00:00Z");
    std::string before = vc2.serializeForSigning();

    sub2.addClaim("role", "admin");
    std::string after = vc2.serializeForSigning();

    check(before == after,
        "sua subject goc KHONG lam doi payload cua VC (subject copy by value)");
    check(vc2.getSubject().getClaim("role") == "user",
        "VC giu nguyen gia tri claim cu");
}

void testSerializeStability() 
{
    printSection("serializeForSigning - on dinh (10 lan lien tuc)");

    DID holderDID("did:example:holder001");
    CredentialSubject subject(holderDID);
    subject.addClaim("name", "Alice");
    subject.addClaim("age", "25");
    subject.addClaim("country", "VN");

    VerifiableCredential vc("vc:003",
        "did:example:issuer001",
        subject,
        "2024-03-15T00:00:00Z");

    std::string first = vc.serializeForSigning();
    bool allSame = true;
    for (int i = 0; i < 10; ++i) {
        if (vc.serializeForSigning() != first) {
            allSame = false;
            break;
        }
    }
    check(allSame,
        "10 lan goi serializeForSigning() lien tiep cho ket qua giong nhau");
}

int main() 
{
    std::cout << "TEST MODULE: CREDENTIAL\n";

    testCredentialSubject();
    testCredentialStatus();
    testDigitalSignature();
    testVerifiableCredential();
    testSerializeStability();

    std::cout << "\nKET QUA: " << g_passed << " PASS / "
        << g_failed << " FAIL\n";

    return g_failed == 0 ? 0 : 1;
}
