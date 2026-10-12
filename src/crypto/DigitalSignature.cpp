#include "crypto/DigitalSignature.h"

// Khởi tạo chữ ký rỗng (chưa ký)
DigitalSignature::DigitalSignature()
    : algorithm(""), keyId(""), value("") {}

// Khởi tạo chữ ký với algorithm, keyId và giá trị
DigitalSignature::DigitalSignature(const std::string& algorithm, const std::string& keyId, const std::string& value)
    : algorithm(algorithm), keyId(keyId), value(value) {}

std::string DigitalSignature::getAlgorithm() const {
    return algorithm;
}

std::string DigitalSignature::getKeyId() const {
    return keyId;
}

std::string DigitalSignature::getValue() const {
    return value;
}

// Trống nếu thiếu giá trị chữ ký hoặc thuật toán
bool DigitalSignature::empty() const {
    return value.empty() || algorithm.empty();
}
