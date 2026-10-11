
#include "identity/DIDDocument.h"

#include <string>
#include <vector>

namespace {
    std::string escapeJson(const std::string& input) {
        std::string result;

        for (unsigned char c : input) {
            switch (c) {
                case '"':
                    result += "\\\"";
                    break;
                case '\\':
                    result += "\\\\";
                    break;
                case '\b':
                    result += "\\b";
                    break;
                case '\f':
                    result += "\\f";
                    break;
                case '\n':
                    result += "\\n";
                    break;
                case '\r':
                    result += "\\r";
                    break;
                case '\t':
                    result += "\\t";
                    break;
                default:
                    if (c < 0x20) {
                        const char hex[] = "0123456789abcdef";
                        result += "\\u00";
                        result += hex[(c >> 4) & 0x0F];
                        result += hex[c & 0x0F];
                    } else {
                        result += static_cast<char>(c);
                    }
            }
        }

        return result;
    }
}

DIDDocument::DIDDocument(const DID& did)
    : did(did), verificationMethods() {}

DID DIDDocument::getDID() const {
    return did;
}

void DIDDocument::addVerificationMethod(
    const VerificationMethod& method) {

    if (method.getId().empty()
        || method.getType().empty()
        || method.getController().empty()
        || method.getPublicKey().empty()) {
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

const VerificationMethod*
DIDDocument::findVerificationMethod(
    const std::string& keyId) const {

    for (const auto& vm : verificationMethods) {
        if (vm.getId() == keyId) {
            return &vm;
        }
    }

    return nullptr;
}

std::string DIDDocument::serialize() const {
    std::string result = "{\n";

    result += "  \"id\": \""
        + escapeJson(did.getValue()) + "\",\n";

    result += "  \"verificationMethod\": [";

    if (!verificationMethods.empty()) {
        result += "\n";
    }

    for (size_t i = 0; i < verificationMethods.size(); ++i) {
        const auto& vm = verificationMethods[i];

        result += "    {\n";
        result += "      \"id\": \""
            + escapeJson(vm.getId()) + "\",\n";
        result += "      \"type\": \""
            + escapeJson(vm.getType()) + "\",\n";
        result += "      \"controller\": \""
            + escapeJson(vm.getController()) + "\",\n";
        result += "      \"publicKeyPem\": \""
            + escapeJson(vm.getPublicKey()) + "\"\n";
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
