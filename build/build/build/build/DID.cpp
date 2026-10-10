
#include "identity/DID.h"
#include <string>

DID::DID() : value("") {}

DID::DID(const std::string& value) : value(value) {}

std::string DID::getValue() const {
    return value;
}

bool DID::isValid() const {

    if (value.rfind("did:", 0) != 0) {
        return false;
    }

    size_t secondColon = value.find(':', 4);

    if (secondColon == std::string::npos) {
        return false;
    }

    if (secondColon == 4) {
        return false;
    }

    if (secondColon == value.length() - 1) {
        return false;
    }

    return true;
}

std::string DID::toString() const {
    return value;
}

bool DID::operator==(const DID& other) const {
    return value == other.value;
}
