#include "identity/DIDDocument.h"

DIDDocument::DIDDocument(const DID& did)
    : did(did) {}

const DID& DIDDocument::getDID() const {
    return did;
}

// Bỏ qua method thiếu field hoặc trùng keyId
void DIDDocument::addVerificationMethod(const VerificationMethod& method) {
    if (method.getId().empty() || method.getType().empty()
        || method.getController().empty() || method.getPublicKey().empty()) {
        return;
    }

    for (const auto& vm : verificationMethods) {
        if (vm.getId() == method.getId()) {
            return;
        }
    }

    verificationMethods.push_back(method);
}

const std::vector<VerificationMethod>&
DIDDocument::getVerificationMethods() const {
    return verificationMethods;
}

// Không thấy keyId thì trả nullptr
const VerificationMethod* DIDDocument::findVerificationMethod(
    const std::string& methodId) const {
    for (const auto& vm : verificationMethods) {
        if (vm.getId() == methodId) {
            return &vm;
        }
    }
    return nullptr;
}

// Chuỗi ổn định để lưu/demo; không chứa private key
std::string DIDDocument::serialize() const {
    std::string result = "{\n";
    result += "  \"id\": \"" + did.getValue() + "\",\n";
    result += "  \"verificationMethod\": [";

    if (!verificationMethods.empty()) {
        result += "\n";
    }

    for (size_t i = 0; i < verificationMethods.size(); ++i) {
        const auto& vm = verificationMethods[i];
        result += "    {\n";
        result += "      \"id\": \"" + vm.getId() + "\",\n";
        result += "      \"type\": \"" + vm.getType() + "\",\n";
        result += "      \"controller\": \"" + vm.getController() + "\",\n";
        result += "      \"publicKeyPem\": \"" + vm.getPublicKey() + "\"\n";
        result += "    }";
        if (i + 1 < verificationMethods.size()) {
            result += ",";
        }
        result += "\n";
    }

    result += "  ]\n";
    result += "}";
    return result;
}
