#pragma once
#include <string>
#include <vector>
#include "identity/DIDDocument.h"

class DIDResolver {
private:
    std::vector<DIDDocument> documents;
public:
    void registerDocument(const DIDDocument& document);
    const DIDDocument* resolve(const std::string& didValue) const;
    bool exists(const std::string& didValue) const;
};
