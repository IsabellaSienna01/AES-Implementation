#pragma once

#include "protocol/messages.hpp"

#include <map>
#include <string>

namespace sm::kdc {

class Kdc {
public:
    explicit Kdc(std::map<std::string, std::string> long_term_keys);
    protocol::Bytes process_request(const protocol::Bytes& payload) const;

private:
    std::map<std::string, std::string> long_term_keys_;
};

}
