#pragma once

#include <string>

namespace sm::network {
class TcpConnection;
}

namespace sm::bob {

class Bob {
public:
    Bob(std::string identity, std::string long_term_key);
    void run(const std::string& bind_host, const std::string& port) const;

private:
    std::string identity_;
    std::string long_term_key_;
    void handle_connection(network::TcpConnection& connection) const;
};

}
