#include <iostream>

#include "actors/Issuer.h"
#include "credential/CredentialSubject.h"
#include "crypto/RSA.h"
#include "identity/DID.h"

int main()
{
    std::cout << "========== DID & VC DEMO ==========\n\n";

    // Demo RSA: data -> sign -> verify -> TRUE
    std::cout << "1) RSA sign / verify\n";
    RSA rsa;
    rsa.generateKeyPair();

    const std::string data = "Hello";
    DigitalSignature signature = rsa.sign(data, "key-1");
    const bool rsaOk = rsa.verify(data, signature, rsa.getPublicKey());

    std::cout << "   data      : " << data << "\n";
    std::cout << "   algorithm : " << signature.getAlgorithm() << "\n";
    std::cout << "   keyId     : " << signature.getKeyId() << "\n";
    std::cout << "   value     : " << signature.getValue() << "\n";
    std::cout << "   verify    : " << (rsaOk ? "TRUE" : "FALSE") << "\n\n";

    // Demo Issuer: tao VC -> ky -> VC co DigitalSignature
    std::cout << "2) Issuer tao va ky VC\n";
    DID issuerDID("did:example:issuer001");
    DID holderDID("did:example:holder001");
    CredentialSubject subject(holderDID);
    subject.addClaim("membership", "active");

    Issuer issuer(issuerDID, rsa, "did:example:issuer001#key-1");
    VerifiableCredential vc = issuer.issueCredential(
        "vc-001",
        subject,
        "2026-10-17");

    std::cout << "   VC id     : " << vc.getId() << "\n";
    std::cout << "   issuer    : " << vc.getIssuerDID() << "\n";
    std::cout << "   hasSignature: " << (vc.hasSignature() ? "true" : "false") << "\n";
    std::cout << "   sig algo  : " << vc.getSignature().getAlgorithm() << "\n";
    std::cout << "   sig keyId : " << vc.getSignature().getKeyId() << "\n";
    std::cout << "   sig value : " << vc.getSignature().getValue() << "\n";

    std::cout << "\n========== DEMO DONE ==========\n";
    return (rsaOk && vc.hasSignature()) ? 0 : 1;
}
