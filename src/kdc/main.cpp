#include "kdc/kdc.hpp"
#include "network/tcp_connection.hpp"
#include "protocol/messages.hpp"

#include <iostream>
#include <map>
#include <stdexcept>
#include <string>

namespace {

std::map<std::string, std::string> parse_keys(int argc, char** argv) {
    if (argc < 7 || (argc - 3) % 2 != 0) {
        throw std::invalid_argument(
            "Usage: kdc <bind-host> <port> --key <identity>=<16-byte-key> "
            "[--key <identity>=<16-byte-key> ...]");
    }
    std::map<std::string, std::string> keys;
    for (int index = 3; index < argc; index += 2) {
        if (std::string(argv[index]) != "--key") {
            throw std::invalid_argument("Expected --key before each identity/key pair");
        }
        const std::string setting(argv[index + 1]);
        const auto separator = setting.find('=');
        if (separator == std::string::npos ||
            !keys.emplace(setting.substr(0, separator), setting.substr(separator + 1)).second) {
            throw std::invalid_argument("Invalid or duplicate KDC identity/key setting");
        }
    }
    return keys;
}

sm::protocol::Bytes error_payload(std::uint16_t code, const std::string& message) {
    sm::protocol::Writer writer;
    writer.uint16(code);
    writer.string_field(message);
    return sm::protocol::encode_message(sm::protocol::MessageType::Error, writer.bytes());
}

}

int main(int argc, char** argv) {
    try {
        const std::string bind_host = argc > 1 ? argv[1] : "";
        const std::string port = argc > 2 ? argv[2] : "";
        if (bind_host.empty() || port.empty()) {
            throw std::invalid_argument(
                "Usage: kdc <bind-host> <port> --key <identity>=<16-byte-key> "
                "[--key <identity>=<16-byte-key> ...]");
        }
        sm::kdc::Kdc kdc(parse_keys(argc, argv));
        auto listener = sm::network::create_tcp_listener(bind_host, port);
        std::cout << "[KDC] [LISTEN] Server ready on " << bind_host << ':' << port << '\n'
                  << "--------------------------------------------------------------------------------" << std::endl;
        for (;;) {
            auto connection = sm::network::accept_tcp(listener);
            try {
                std::cout << "[KDC] [REQUEST] Incoming connection from " << connection.peer_address() << std::endl;
                const auto request = connection.receive_frame();
                const auto response = kdc.process_request(request);
                connection.send_frame(response);
                std::cout << "[KDC] [RESPONSE] Dispatched KdcResponse (" << response.size() << " bytes) to Alice.\n"
                          << "--------------------------------------------------------------------------------" << std::endl;
            } catch (const std::exception& error) {
                try {
                    connection.send_frame(error_payload(0x0001, "Invalid KDC request"));
                } catch (const std::exception& send_error) {
                    std::cerr << "Could not send KDC error response: "
                              << send_error.what() << std::endl;
                }
                std::cerr << "[KDC] [REJECT] Rejected connection: " << error.what() << '\n'
                          << "--------------------------------------------------------------------------------" << std::endl;
            }
        }
    } catch (const std::exception& error) {
        std::cerr << "KDC startup failed: " << error.what() << '\n';
        return 1;
    }
}
