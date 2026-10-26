#include "bob/bob.hpp"

#include "crypto/aes.hpp"
#include "common/secure_random.hpp"
#include "network/tcp_connection.hpp"
#include "protocol/messages.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <utility>

namespace sm::bob {
namespace {

protocol::Bytes decrypt_object(const std::string& key, const protocol::Bytes& object) {
    if (key.size() != 16 || object.size() < 32 || (object.size() - 16) % 16 != 0) {
        throw std::invalid_argument("Malformed encrypted object");
    }
    const protocol::Bytes iv(object.begin(), object.begin() + 16);
    const protocol::Bytes ciphertext(object.begin() + 16, object.end());
    return AES(key).decrypt_cbc(ciphertext, iv);
}

protocol::Bytes encrypt_object(const std::string& key, const protocol::Bytes& plaintext) {
    const auto iv = secure_random_bytes(16);
    const auto ciphertext = AES(key).encrypt_cbc(plaintext, iv);
    auto object = iv;
    object.insert(object.end(), ciphertext.begin(), ciphertext.end());
    return object;
}

protocol::Bytes wrap(protocol::MessageType type, const protocol::Bytes& body) {
    return protocol::encode_message(type, body);
}

protocol::Bytes increment_nonce(protocol::Bytes nonce) {
    for (auto it = nonce.rbegin(); it != nonce.rend(); ++it) {
        ++*it;
        if (*it != 0) {
            break;
        }
    }
    return nonce;
}

bool same_bytes(const protocol::Bytes& left, const protocol::Bytes& right) {
    if (left.size() != right.size()) {
        return false;
    }
    unsigned char difference = 0;
    for (std::size_t index = 0; index < left.size(); ++index) {
        difference |= static_cast<unsigned char>(left[index] ^ right[index]);
    }
    return difference == 0;
}

bool is_ascii(const protocol::Bytes& bytes) {
    return std::all_of(bytes.begin(), bytes.end(),
                       [](unsigned char value) { return value <= 0x7f; });
}

struct ChatPacket {
    std::string sender;
    std::uint64_t sequence{};
    protocol::Bytes encrypted_object;
    protocol::Bytes tag;
};

ChatPacket decode_chat(const protocol::Bytes& body) {
    protocol::Reader reader(body);
    ChatPacket packet{reader.string_field(), reader.uint64(),
                      reader.field(), reader.field(32)};
    reader.require_done();
    if (packet.encrypted_object.size() < 32 ||
        (packet.encrypted_object.size() - 16) % 16 != 0 || !packet.tag.empty()) {
        throw std::invalid_argument("Invalid or unsupported chat message");
    }
    return packet;
}

protocol::Bytes encode_chat(const std::string& sender, std::uint64_t sequence,
                            const protocol::Bytes& encrypted_object) {
    protocol::Writer writer;
    writer.string_field(sender);
    writer.uint64(sequence);
    writer.field(encrypted_object);
    writer.field({});
    return wrap(protocol::MessageType::ChatMessage, writer.bytes());
}

}

Bob::Bob(std::string identity, std::string long_term_key)
    : identity_(std::move(identity)), long_term_key_(std::move(long_term_key)) {
    if (!protocol::valid_id(identity_) || long_term_key_.size() != 16 ||
        !std::all_of(long_term_key_.begin(), long_term_key_.end(),
                     [](unsigned char value) { return value <= 0x7f; })) {
        throw std::invalid_argument("Bob requires a valid identity and a 16-byte ASCII key");
    }
}

void Bob::run(const std::string& bind_host, const std::string& port) const {
    auto listener = network::create_tcp_listener(bind_host, port);
    std::cout << "Bob " << identity_ << " listening on " << bind_host << ':' << port << '\n';
    for (;;) {
        auto connection = network::accept_tcp(listener);
        try {
            handle_connection(connection);
        } catch (const std::exception& error) {
            std::cerr << "Bob rejected a connection: " << error.what() << '\n';
        }
    }
}

void Bob::handle_connection(network::TcpConnection& connection) const {
    protocol::Bytes body;
    if (protocol::decode_message(connection.receive_frame(), body) !=
        protocol::MessageType::BobTicket) {
        throw std::invalid_argument("Expected BOB_TICKET");
    }
    const auto ticket = protocol::decode_length_prefixed(body);
    const auto ticket_plaintext = decrypt_object(long_term_key_, ticket);
    protocol::Reader ticket_reader(ticket_plaintext);
    const auto session_key_bytes = ticket_reader.fixed(16);
    const auto alice_id = ticket_reader.string_field();
    ticket_reader.require_done();
    if (!protocol::valid_id(alice_id)) {
        throw std::invalid_argument("Ticket contains an invalid initiator identity");
    }
    const std::string session_key(session_key_bytes.begin(), session_key_bytes.end());

    const auto nonce = secure_random_bytes(16);
    const auto challenge = encrypt_object(session_key, nonce);
    connection.send_frame(wrap(protocol::MessageType::Challenge,
                               protocol::encode_length_prefixed(challenge)));

    if (protocol::decode_message(connection.receive_frame(), body) !=
        protocol::MessageType::ChallengeResponse) {
        throw std::invalid_argument("Expected CHALLENGE_RESPONSE");
    }
    const auto encrypted_response = protocol::decode_length_prefixed(body);
    const auto response = decrypt_object(session_key, encrypted_response);
    if (!same_bytes(response, increment_nonce(nonce))) {
        throw std::runtime_error("Authentication failed");
    }

    std::cout << "Authenticated Alice " << alice_id
              << "; chat is confidentiality-only (no message authentication)\n";
    std::atomic_bool receive_finished{false};
    std::thread receiver([&] {
        std::uint64_t expected_sequence = 0;
        try {
            while (!receive_finished.load()) {
                const auto incoming = connection.receive_frame();
                if (protocol::decode_message(incoming, body) !=
                    protocol::MessageType::ChatMessage) {
                    throw std::invalid_argument("Expected CHAT_MESSAGE after authentication");
                }
                const auto packet = decode_chat(body);
                if (packet.sender != alice_id || packet.sequence != expected_sequence) {
                    throw std::runtime_error("Invalid chat sender or sequence number");
                }
                const auto plaintext = decrypt_object(session_key, packet.encrypted_object);
                if (!is_ascii(plaintext)) {
                    throw std::runtime_error("Received chat message is not ASCII");
                }
                std::cout << alice_id << ": "
                          << std::string(plaintext.begin(), plaintext.end()) << '\n';
                ++expected_sequence;
            }
        } catch (const std::exception& error) {
            if (!receive_finished.load()) {
                std::cerr << "Chat receive failed: " << error.what() << '\n';
            }
        }
        receive_finished = true;
    });

    std::string line;
    std::uint64_t outgoing_sequence = 0;
    std::exception_ptr send_failure;
    try {
        while (!receive_finished.load() && std::getline(std::cin, line)) {
            if (line == "/quit") {
                break;
            }
            const protocol::Bytes plaintext(line.begin(), line.end());
            if (!is_ascii(plaintext)) {
                std::cerr << "Only ASCII chat messages are supported\n";
                continue;
            }
            const auto encrypted = encrypt_object(session_key, plaintext);
            connection.send_frame(encode_chat(identity_, outgoing_sequence++, encrypted));
        }
    } catch (...) {
        send_failure = std::current_exception();
    }
    receive_finished = true;
    connection.shutdown();
    receiver.join();
    if (send_failure) {
        std::rethrow_exception(send_failure);
    }
}

}
