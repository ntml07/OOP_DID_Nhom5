#include "identity/DIDResolver.h"

// Đăng ký document; trùng DID thì ghi đè
void DIDResolver::registerDocument(const DIDDocument& document) {
    const std::string didValue = document.getDID().getValue();
    for (auto& doc : documents) {
        if (doc.getDID().getValue() == didValue) {
            doc = document;
            return;
        }
    }
    documents.push_back(document);
}

// Không có DID thì trả nullptr
const DIDDocument* DIDResolver::resolve(const std::string& didValue) const {
    for (const auto& doc : documents) {
        if (doc.getDID().getValue() == didValue) {
            return &doc;
        }
    }
    return nullptr;
}

bool DIDResolver::exists(const std::string& didValue) const {
    return resolve(didValue) != nullptr;
}
