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
#include "identity/DIDDocument.h"
#include "identity/DIDResolver.h"
#include "identity/VerificationMethod.h"
#include "zkp/SchnorrZKP.h"

namespace {

struct AppState {
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
};

void printMenu()
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

bool requireIdentities(const AppState& app)
{
    if (!app.identitiesReady)
    {
        std::cout << "Can khoi tao danh tinh truoc (chon 1)\n";
        return false;
    }
    return true;
}

bool requireWalletVc(const AppState& app)
{
    if (!requireIdentities(app))
    {
        return false;
    }
    if (app.holder->getCredentials().empty())
    {
        std::cout << "Vi chua co VC. Hay cap VC truoc (chon 2)\n";
        return false;
    }
    return true;
}

bool requirePresented(const AppState& app)
{
    if (!app.hasPresented || app.presentedVc == nullptr)
    {
        std::cout << "Chua xuat trinh VC (chon 4)\n";
        return false;
    }
    return true;
}

bool requireProof(const AppState& app)
{
    if (!app.hasProof)
    {
        std::cout << "Chua co ZKP. Hay tao proof truoc (chon 6)\n";
        return false;
    }
    return true;
}

std::string makeVcId(int index)
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

void actionInit(AppState& app)
{
    if (app.identitiesReady)
    {
        std::cout << "Danh tinh da duoc khoi tao. Khong tao lai\n";
        return;
    }

    app.rsa.generateKeyPair();

    DID issuerDID("did:example:issuer001");
    const std::string issuerKeyId = "did:example:issuer001#key-1";
    app.issuer = std::make_unique<Issuer>(issuerDID, app.rsa, issuerKeyId);

    DIDDocument issuerDoc(issuerDID);
    issuerDoc.addVerificationMethod(VerificationMethod(
        issuerKeyId,
        "RsaVerificationKey",
        issuerDID.toString(),
        app.issuer->getPublicKey()));
    app.resolver.registerDocument(issuerDoc);

    DID holderDID("did:example:holder001");
    app.holder = std::make_unique<Holder>(holderDID);
    app.holder->setSchnorrSecret(7);

    const long long publicValue = app.holder->createSchnorrPublicValue(app.zkp);
    DIDDocument holderDoc(holderDID);
    holderDoc.addVerificationMethod(VerificationMethod(
        app.holder->getSchnorrMethodId(),
        "SchnorrVerificationKey",
        holderDID.toString(),
        std::to_string(publicValue)));
    app.resolver.registerDocument(holderDoc);

    app.verifier = std::make_unique<Verifier>(DID("did:example:verifier001"));
    app.identitiesReady = true;

    std::cout << "Khoi tao thanh cong.\n"
              << "  Issuer DID : " << app.issuer->getDID().getValue() << "\n"
              << "  Holder DID : " << app.holder->getDID().getValue() << "\n"
              << "  Verifier DID: " << app.verifier->getDID().getValue() << "\n";
}

void actionIssue(AppState& app)
{
    if (!requireIdentities(app))
    {
        return;
    }

    const std::string vcId = makeVcId(app.nextVcIndex);
    ++app.nextVcIndex;

    CredentialSubject subject(app.holder->getDID());
    subject.addClaim("name", "Nguyen Van A");
    subject.addClaim("membership", "active");

    VerifiableCredential vc = app.issuer->issueCredential(
        vcId,
        subject,
        "2026-10-17");
    app.holder->receiveCredential(vc);
    app.lastIssuedId = vcId;

    std::cout << "Da cap VC va luu vao vi Holder\n"
              << "  VC ID: " << vcId << "\n"
              << "  Issuer: " << vc.getIssuerDID() << "\n";
}

void actionWallet(AppState& app)
{
    if (!requireIdentities(app))
    {
        return;
    }

    const auto& wallet = app.holder->getCredentials();
    if (wallet.empty())
    {
        std::cout << "Vi dang trong.\n";
        return;
    }

    std::cout << "Vi chung chi (" << wallet.size() << "):\n";
    for (size_t i = 0; i < wallet.size(); ++i)
    {
        const VerifiableCredential& vc = wallet[i];
        std::cout << "  " << (i + 1) << ") ID=" << vc.getId()
                  << " | issuer=" << vc.getIssuerDID()
                  << " | subject=" << vc.getSubject().getDID().getValue()
                  << " | status=" << vc.getStatus().toString();
        if (vc.getSubject().hasClaim("name"))
        {
            std::cout << " | name=" << vc.getSubject().getClaim("name");
        }
        std::cout << "\n";
    }
}

void actionPresent(AppState& app)
{
    if (!requireWalletVc(app))
    {
        return;
    }

    const std::string& id = app.lastIssuedId;
    const VerifiableCredential* found = app.holder->findCredential(id);
    if (found == nullptr)
    {
        const auto& wallet = app.holder->getCredentials();
        found = &wallet.back();
    }

    app.presentedVc = std::make_unique<VerifiableCredential>(*found);
    app.hasPresented = true;

    std::cout << "Holder xuat trinh VC:\n";
    app.presentedVc->display();
    std::cout << "\n";
}

void actionVerifyVc(AppState& app)
{
    if (!requireIdentities(app) || !requirePresented(app))
    {
        return;
    }

    const bool ok = app.verifier->verifyCredential(
        *app.presentedVc,
        app.resolver,
        app.rsa,
        *app.issuer);

    std::cout << "Xac minh VC (RSA): " << (ok ? "VALID" : "INVALID") << "\n";
}

void actionCreateZkp(AppState& app)
{
    if (!requireIdentities(app) || !requireWalletVc(app))
    {
        return;
    }

    app.sessionChallenge = "session-" + makeVcId(app.nextVcIndex) + "-zkp";
    app.lastProof = app.holder->createOwnershipProof(app.zkp, app.sessionChallenge);
    app.hasProof = true;

    std::cout << "Da tao ZKP (kiem soat DID Holder).\n"
              << "  Challenge da luu: " << app.sessionChallenge << "\n";
}

void actionVerifyZkp(AppState& app)
{
    if (!requireIdentities(app) || !requirePresented(app) || !requireProof(app))
    {
        return;
    }

    const bool ok = app.verifier->verifyHolderControl(
        *app.presentedVc,
        app.lastProof,
        app.holder->getDID().getValue(),
        app.sessionChallenge,
        app.resolver,
        app.zkp);

    std::cout << "Xac minh ZKP (DID control): " << (ok ? "VALID" : "INVALID") << "\n";
}

void actionRevoke(AppState& app)
{
    if (!requireIdentities(app))
    {
        return;
    }

    std::string id = app.lastIssuedId;
    if (app.hasPresented && app.presentedVc != nullptr)
    {
        id = app.presentedVc->getId();
    }

    if (id.empty())
    {
        std::cout << "Chua co VC de thu hoi (hay cap VC truoc)\n";
        return;
    }

    // Main block: Issuer-side revoke by ID (does not mutate Holder wallet VC)
    const bool ok = app.issuer->revokeCredential(id);
    if (!ok)
    {
        std::cout << "Thu hoi that bai: VC " << id
                  << " khong do Issuer nay cap hoac da thu hoi\n";
        return;
    }

    std::cout << "Issuer da thu hoi VC " << id << "\n";
}

void actionFullDemo(AppState& app)
{
    std::cout << "\nDEMO DAY DU\n";

    if (!app.identitiesReady)
    {
        std::cout << "\nBuoc 1: Khoi tao danh tinh\n";
        actionInit(app);
    }
    else
    {
        std::cout << "\nBuoc 1: Bo qua (da khoi tao)\n";
    }

    if (app.holder->getCredentials().empty())
    {
        std::cout << "\nBuoc 2: Cap VC\n";
        actionIssue(app);
    }
    else
    {
        std::cout << "\nBuoc 2: Bo qua cap VC moi (vi da co VC)\n";
        if (app.lastIssuedId.empty())
        {
            app.lastIssuedId = app.holder->getCredentials().back().getId();
        }
    }

    std::cout << "\nBuoc 3: Xem vi\n";
    actionWallet(app);

    std::cout << "\nBuoc 4: Xuat trinh VC\n";
    actionPresent(app);

    std::cout << "\nBuoc 5: Xac minh VC\n";
    actionVerifyVc(app);

    std::cout << "\nBuoc 6: Tao ZKP\n";
    actionCreateZkp(app);

    std::cout << "\nBuoc 7: Xac minh ZKP\n";
    actionVerifyZkp(app);

    std::cout << "\nBuoc 8: Issuer thu hoi VC\n";
    actionRevoke(app);

    std::cout << "\nBuoc 5 lai: Xac minh VC sau thu hoi (ky vong INVALID)\n";
    actionVerifyVc(app);

    std::cout << "\nDEMO END\n";
}

}

int main()
{
    AppState app;
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
            actionInit(app);
        }
        else if (choice == "2")
        {
            actionIssue(app);
        }
        else if (choice == "3")
        {
            actionWallet(app);
        }
        else if (choice == "4")
        {
            actionPresent(app);
        }
        else if (choice == "5")
        {
            actionVerifyVc(app);
        }
        else if (choice == "6")
        {
            actionCreateZkp(app);
        }
        else if (choice == "7")
        {
            actionVerifyZkp(app);
        }
        else if (choice == "8")
        {
            actionRevoke(app);
        }
        else if (choice == "9")
        {
            actionFullDemo(app);
        }
        else
        {
            std::cout << "Lua chon khong hop le\n";
        }
    }

    return 0;
}
