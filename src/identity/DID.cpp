#include "identity/DID.h"

// Khởi tạo DID rỗng
DID::DID() : value("") {}

// Khởi tạo DID từ chuỗi
DID::DID(const std::string& value) : value(value) {}

std::string DID::getValue() const {
    return value;
}

// Hợp lệ khi dạng did:<method>:<id>
bool DID::isValid() const {
    if (value.rfind("did:", 0) != 0) {
        return false;
    }

    const size_t secondColon = value.find(':', 4);
    if (secondColon == std::string::npos || secondColon == 4) {
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

// Hai DID bằng nhau khi cùng chuỗi định danh
bool DID::operator==(const DID& other) const {
    return value == other.value;
}
