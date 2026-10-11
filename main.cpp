#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <cassert>

class DID {
private:
    std::string value;

public:
    DID() : value("") {}
    explicit DID(const std::string& value) : value(value) {}

    std::string getValue() const {
        return value;
    }

    bool isValid() const {
        if (value.size() < 7 || value.compare(0, 4, "did:") != 0) {
            return false;
        }

        size_t methodEnd = value.find(':', 4);

        if (methodEnd == std::string::npos || methodEnd == 4) {
            return false;
        }

        if (methodEnd + 1 >= value.size()) {
            return false;
        }

        return true;
    }

    std::string toString() const {
        return value;
    }

    bool operator==(const DID& other) const {
        return value == other.value;
    }
};

class VerificationMethod {
private:
    std::string id;
    std::string type;
    std::string controller;
    std::string publicKey;

public:
    VerificationMethod()
        : id(""), type(""), controller(""), publicKey("") {}

    VerificationMethod(const std::string& id,
                       const std::string& type,
                       const std::string& controller,
                       const std::string& publicKey)
        : id(id), type(type), controller(controller),
          publicKey(publicKey) {}

    std::string getId() const {
        return id;
    }

    std::string getType() const {
        return type;
    }

    std::string getController() const {
        return controller;
    }

    std::string getPublicKey() const {
        return publicKey;
    }
};

class DIDDocument {
private:
    DID id;
    std::vector<VerificationMethod> verificationMethods;

    static std::string escapeJson(const std::string& s) {
        std::ostringstream out;

        for (unsigned char c : s) {
            switch (c) {
                case '"':
                    out << "\\\"";
                    break;
                case '\\':
                    out << "\\\\";
                    break;
                case '\b':
                    out << "\\b";
                    break;
                case '\f':
                    out << "\\f";
                    break;
                case '\n':
                    out << "\\n";
                    break;
                case '\r':
                    out << "\\r";
                    break;
                case '\t':
                    out << "\\t";
                    break;
                default:
                    if (c < 0x20) {
                        const char hex[] = "1234567898abcdef";
                        out << "\\u00"
                            << hex[(c >> 4) & 0x0f]
                            << hex[c & 0x0f];
                    } else {
                        out << static_cast<char>(c);
                    }
            }
        }

        return out.str();
    }

public:
    DIDDocument() : id(DID("")) {}
    explicit DIDDocument(const DID& id) : id(id) {}

    DID getId() const {
        return id;
    }

    void addVerificationMethod(const VerificationMethod& vm) {
        verificationMethods.push_back(vm);
    }

    const std::vector<VerificationMethod>&
    getVerificationMethods() const {
        return verificationMethods;
    }

    const VerificationMethod* findVerificationMethod(
        const std::string& keyId) const {

        for (const auto& vm : verificationMethods) {
            if (vm.getId() == keyId) {
                return &vm;
            }
        }

        return nullptr;
    }

    std::string serialize() const {
        std::ostringstream oss;

        oss << "{\n";
        oss << "  \"id\": \"" << escapeJson(id.getValue()) << "\",\n";
        oss << "  \"verificationMethod\": [\n";

        for (size_t i = 0; i < verificationMethods.size(); ++i) {
            const auto& vm = verificationMethods[i];

            oss << "    {\n";
            oss << "      \"id\": \""
                << escapeJson(vm.getId()) << "\",\n";
            oss << "      \"type\": \""
                << escapeJson(vm.getType()) << "\",\n";
            oss << "      \"controller\": \""
                << escapeJson(vm.getController()) << "\",\n";
            oss << "      \"publicKey\": \""
                << escapeJson(vm.getPublicKey()) << "\"\n";
            oss << "    }";

            if (i + 1 < verificationMethods.size()) {
                oss << ",";
            }

            oss << "\n";
        }

        oss << "  ]\n";
        oss << "}";

        return oss.str();
    }
};

class DIDResolver {
private:
    std::unordered_map<std::string, DIDDocument> documents;

public:
    DIDResolver() = default;

    bool registerDocument(const DIDDocument& doc) {
        DID docId = doc.getId();

        if (!docId.isValid()) {
            return false;
        }

        const std::string didStr = docId.getValue();

        if (documents.find(didStr) != documents.end()) {
            return false;
        }

        documents.emplace(didStr, doc);
        return true;
    }

    const DIDDocument* resolve(const std::string& didString) const {
        auto it = documents.find(didString);

        if (it != documents.end()) {
            return &(it->second);
        }

        return nullptr;
    }

    bool exists(const std::string& didString) const {
        return documents.find(didString) != documents.end();
    }
};

int main() {
    std::cout << "=== DEMO LUONG QUAN LY IDENTITY (DID) ===\n\n";

    DID issuerDID("did:example:issuer001");
    assert(issuerDID.isValid());

    std::cout << "[1] Tao DID thanh cong: "
              << issuerDID.getValue() << "\n";

    std::string keyId = "did:example:issuer001#key-1";
    std::string publicKey =
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ...";

    VerificationMethod vm(
        keyId,
        "RsaVerificationKey2020",
        issuerDID.getValue(),
        publicKey
    );

    std::cout << "[2] Tao VerificationMethod cho Key ID: "
              << vm.getId() << "\n";

    DIDDocument doc(issuerDID);
    doc.addVerificationMethod(vm);

    std::cout << "[3] Gan Public Key vao DID Document thanh cong.\n";

    DIDResolver resolver;
    bool registered = resolver.registerDocument(doc);

    assert(registered);

    std::cout << "[4] Dang ky DID Document vao Resolver thanh cong.\n\n";

    std::cout << "--- TIEN HANH TIM KIEM (RESOLVE) ---\n";

    const DIDDocument* retrievedDoc =
        resolver.resolve("did:example:issuer001");

    if (retrievedDoc != nullptr) {
        std::cout << "-> Tim thay DID Document: "
                  << retrievedDoc->getId().getValue() << "\n";

        const VerificationMethod* retrievedVm =
            retrievedDoc->findVerificationMethod(keyId);

        if (retrievedVm != nullptr) {
            std::cout << "-> Tim thay Public Key tuong ung:\n";
            std::cout << "   - Key ID: "
                      << retrievedVm->getId() << "\n";
            std::cout << "   - Algorithm: "
                      << retrievedVm->getType() << "\n";
            std::cout << "   - Controller: "
                      << retrievedVm->getController() << "\n";
            std::cout << "   - Public Key Value: "
                      << retrievedVm->getPublicKey() << "\n\n";
        } else {
            std::cout << "-> KHONG tim thay VerificationMethod voi keyId: "
                      << keyId << "\n\n";
        }

        std::cout << "--- TOAN BO DU LIEU DID DOCUMENT (SERIALIZE) ---\n";
        std::cout << retrievedDoc->serialize() << "\n";
    } else {
        std::cout << "-> KHONG tim thay DID Document trong Resolver!\n";
    }

    return 0;
}