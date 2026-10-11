
#include "identity/DIDResolver.h"

#include <string>
#include <unordered_map>

bool DIDResolver::registerDocument(const DIDDocument& doc) {
    const DID did = doc.getDID();

    if (!did.isValid()) {
        return false;
    }

    const std::string didStr = did.getValue();

    documents.insert_or_assign(didStr, doc);

    return true;
}

const DIDDocument* DIDResolver::resolve(
    const std::string& didString) const {

    const auto it = documents.find(didString);

    if (it == documents.end()) {
        return nullptr;
    }

    return &it->second;
}

bool DIDResolver::exists(const std::string& didString) const {
    return documents.find(didString) != documents.end();
}
