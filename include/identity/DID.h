#pragma once
#include <string>

class DID {
private:
    std::string value;
public:
    DID();
    DID(const std::string& value);
    std::string getValue() const;
    bool isValid() const;
    std::string toString() const;
    bool operator==(const DID& other) const;
};
