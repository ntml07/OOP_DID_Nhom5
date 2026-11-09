#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "actors/Holder.h"
#include "actors/Issuer.h"
#include "actors/Verifier.h"
#include "credential/CredentialSubject.h"
#include "crypto/RSA.h"
#include "identity/DID.h"
#include "identity/DIDResolver.h"
#include "zkp/SchnorrZKP.h"

// Lớp ứng dụng giữ các đối tượng DID/VC và điều khiển menu.
class VerifiableCredentialApp {
private:
    bool identitiesReady = false;
    RSA rsa;
    SchnorrZKP zkp;
    DIDResolver resolver;
    std::unique_ptr<Issuer> issuer;
    std::unique_ptr<Holder> holder;
    std::unique_ptr<Verifier> verifier;

    int nextVcIndex = 1;
    std::string lastIssuedId;

    bool hasPresented = false;
    std::unique_ptr<VerifiableCredential> presentedVc;

    std::string sessionChallenge;
    ZKPProofData lastProof{};
    bool hasProof = false;

    void printMenu() const;
    bool requireIdentities() const;
    bool requireWalletVc() const;
    bool requirePresented() const;
    bool requireProof() const;
    std::string makeVcId(int index) const;

    void initIdentities();
    void issueCredential();
    void showWallet() const;
    void presentCredential();
    void verifyCredential() const;
    void createProof();
    void verifyProof() const;
    void revokeCredential();
    void runDemo();

public:
    void run();
};

void VerifiableCredentialApp::printMenu() const
{
    std::cout << "\nHE THONG DID & VC\n\n"
              << "1. Khoi tao danh tinh\n"
              << "2. Issuer cap bang chung nhan (VC)\n"
              << "3. Holder xem vi chung chi\n"
              << "4. Holder xuat trinh VC\n"
              << "5. Verifier xac minh VC\n"
              << "6. Holder tao ZKP\n"
              << "7. Verifier xac minh ZKP\n"
              << "8. Issuer thu hoi VC\n"
              << "9. Chay demo day du\n"
              << "0. Thoat\n\n"
              << "Nhap lua chon: ";
}

bool VerifiableCredentialApp::requireIdentities() const
{
    if (!identitiesReady)
    {
        std::cout << "Can khoi tao danh tinh truoc (chon 1)\n";
        return false;
    }
    return true;
}

bool VerifiableCredentialApp::requireWalletVc() const
{
    if (!requireIdentities())
    {
        return false;
    }
    if (holder->getCredentials().empty())
    {
        std::cout << "Vi chua co VC. Hay cap VC truoc (chon 2)\n";
        return false;
    }
    return true;
}

bool VerifiableCredentialApp::requirePresented() const
{
    if (!hasPresented || presentedVc == nullptr)
    {
        std::cout << "Chua xuat trinh VC (chon 4)\n";
        return false;
    }
    return true;
}

bool VerifiableCredentialApp::requireProof() const
{
    if (!hasProof)
    {
        std::cout << "Chua co ZKP. Hay tao proof truoc (chon 6)\n";
        return false;
    }
    return true;
}

std::string VerifiableCredentialApp::makeVcId(int index) const
{
    std::ostringstream oss;
    oss << "vc-";
    if (index < 10)
    {
        oss << "00";
    }
    else if (index < 100)
    {
        oss << "0";
    }
    oss << index;
    return oss.str();
}

void VerifiableCredentialApp::initIdentities()
{
    // Main block: tạo Actor, mỗi Actor tự dựng Document, App chỉ đăng ký
    if (identitiesReady)
    {
        std::cout << "Danh tinh da duoc khoi tao. Khong tao lai\n";
        return;
    }

    rsa.generateKeyPair();

    issuer = std::make_unique<Issuer>(
        DID("did:example:issuer001"),
        rsa,
        "did:example:issuer001#key-1");
    resolver.registerDocument(issuer->createDidDocument());

    holder = std::make_unique<Holder>(DID("did:example:holder001"));
    holder->setSchnorrSecret(7);
    resolver.registerDocument(holder->createDidDocument(zkp));

    verifier = std::make_unique<Verifier>(DID("did:example:verifier001"));
    identitiesReady = true;

    std::cout << "Khoi tao thanh cong.\n"
              << "  Issuer DID : " << issuer->getDID().getValue() << "\n"
              << "  Holder DID : " << holder->getDID().getValue() << "\n"
              << "  Verifier DID: " << verifier->getDID().getValue() << "\n";
}

void VerifiableCredentialApp::issueCredential()
{
    // Main block: Issuer cấp/ký VC, Holder nhận vào ví
    if (!requireIdentities())
    {
        return;
    }

    const std::string vcId = makeVcId(nextVcIndex);
    ++nextVcIndex;

    CredentialSubject subject(holder->getDID());
    subject.addClaim("name", "Nguyen Van A");
    subject.addClaim("membership", "active");

    VerifiableCredential vc = issuer->issueCredential(
        vcId,
        subject,
        "2026-10-17");
    holder->receiveCredential(vc);
    lastIssuedId = vcId;

    std::cout << "Da cap VC va luu vao vi Holder\n"
              << "  VC ID: " << vcId << "\n"
              << "  Issuer: " << vc.getIssuerDID() << "\n";
}

void VerifiableCredentialApp::showWallet() const
{
    // Main block: nhờ Holder tự in ví
    if (!requireIdentities())
    {
        return;
    }
    holder->showWallet();
}

void VerifiableCredentialApp::presentCredential()
{
    // Main block: xuất trình đúng VC theo lastIssuedId, không tự chọn VC khác
    if (!requireWalletVc())
    {
        return;
    }

    if (lastIssuedId.empty())
    {
        std::cout << "Chua co VC de xuat trinh\n";
        return;
    }

    const VerifiableCredential* found = holder->findCredential(lastIssuedId);
    if (found == nullptr)
    {
        std::cout << "Khong tim thay VC " << lastIssuedId << " trong vi\n";
        return;
    }

    presentedVc = std::make_unique<VerifiableCredential>(*found);
    hasPresented = true;

    std::cout << "Holder xuat trinh VC:\n";
    presentedVc->display();
    std::cout << "\n";
}

void VerifiableCredentialApp::verifyCredential() const
{
    // Main block: Verifier xác minh VC qua Resolver + RSA
    if (!requireIdentities() || !requirePresented())
    {
        return;
    }

    const bool ok = verifier->verifyCredential(
        *presentedVc,
        resolver,
        rsa,
        *issuer);

    std::cout << "Xac minh VC (RSA): " << (ok ? "VALID" : "INVALID") << "\n";
}

void VerifiableCredentialApp::createProof()
{
    // Main block: Holder tạo proof kiểm soát DID
    if (!requireIdentities() || !requireWalletVc())
    {
        return;
    }

    sessionChallenge = "session-" + makeVcId(nextVcIndex) + "-zkp";
    lastProof = holder->createOwnershipProof(zkp, sessionChallenge);
    hasProof = true;

    std::cout << "Da tao ZKP (kiem soat DID Holder).\n"
              << "  Challenge da luu: " << sessionChallenge << "\n";
}

void VerifiableCredentialApp::verifyProof() const
{
    // Main block: Verifier kiểm proof DID-control
    if (!requireIdentities() || !requirePresented() || !requireProof())
    {
        return;
    }

    const bool ok = verifier->verifyHolderControl(
        *presentedVc,
        lastProof,
        holder->getDID().getValue(),
        sessionChallenge,
        resolver,
        zkp);

    std::cout << "Xac minh ZKP (DID control): " << (ok ? "VALID" : "INVALID") << "\n";
}

void VerifiableCredentialApp::revokeCredential()
{
    // Main block: Issuer thu hồi theo ID, không sửa VC trong ví
    if (!requireIdentities())
    {
        return;
    }

    std::string id = lastIssuedId;
    if (hasPresented && presentedVc != nullptr)
    {
        id = presentedVc->getId();
    }

    if (id.empty())
    {
        std::cout << "Chua co VC de thu hoi (hay cap VC truoc)\n";
        return;
    }

    const bool ok = issuer->revokeCredential(id);
    if (!ok)
    {
        std::cout << "Thu hoi that bai: VC " << id
                  << " khong do Issuer nay cap hoac da thu hoi\n";
        return;
    }

    std::cout << "Issuer da thu hoi VC " << id << "\n";
}

void VerifiableCredentialApp::runDemo()
{
    // Main block: chạy end-to-end tới thu hồi rồi verify lại
    std::cout << "\nDEMO DAY DU\n";

    if (!identitiesReady)
    {
        std::cout << "\nBuoc 1: Khoi tao danh tinh\n";
        initIdentities();
    }
    else
    {
        std::cout << "\nBuoc 1: Bo qua (da khoi tao)\n";
    }

    if (holder->getCredentials().empty())
    {
        std::cout << "\nBuoc 2: Cap VC\n";
        issueCredential();
    }
    else
    {
        std::cout << "\nBuoc 2: Bo qua cap VC moi (vi da co VC)\n";
        if (lastIssuedId.empty())
        {
            lastIssuedId = holder->getCredentials().back().getId();
        }
    }

    std::cout << "\nBuoc 3: Xem vi\n";
    showWallet();

    std::cout << "\nBuoc 4: Xuat trinh VC\n";
    presentCredential();

    std::cout << "\nBuoc 5: Xac minh VC\n";
    verifyCredential();

    std::cout << "\nBuoc 6: Tao ZKP\n";
    createProof();

    std::cout << "\nBuoc 7: Xac minh ZKP\n";
    verifyProof();

    std::cout << "\nBuoc 8: Issuer thu hoi VC\n";
    revokeCredential();

    std::cout << "\nBuoc 5 lai: Xac minh VC sau thu hoi (ky vong INVALID)\n";
    verifyCredential();

    std::cout << "\nDEMO END\n";
}

void VerifiableCredentialApp::run()
{
    // Main block: vòng lặp menu gọi method của ứng dụng
    std::cout << "He thong DID + Verifiable Credential\n";

    while (true)
    {
        printMenu();
        std::string choice;
        if (!(std::cin >> choice))
        {
            break;
        }

        if (choice == "0")
        {
            std::cout << "Thoat\n";
            break;
        }
        if (choice == "1")
        {
            initIdentities();
        }
        else if (choice == "2")
        {
            issueCredential();
        }
        else if (choice == "3")
        {
            showWallet();
        }
        else if (choice == "4")
        {
            presentCredential();
        }
        else if (choice == "5")
        {
            verifyCredential();
        }
        else if (choice == "6")
        {
            createProof();
        }
        else if (choice == "7")
        {
            verifyProof();
        }
        else if (choice == "8")
        {
            revokeCredential();
        }
        else if (choice == "9")
        {
            runDemo();
        }
        else
        {
            std::cout << "Lua chon khong hop le\n";
        }
    }
}

int main()
{
    VerifiableCredentialApp app;
    app.run();
    return 0;
}
