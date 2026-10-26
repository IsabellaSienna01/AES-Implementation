#include "alice/alice.hpp"

#include "common/secure_random.hpp"
#include "crypto/aes.hpp"
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

namespace sm::alice {
namespace {
    protocol::Bytes encrypt_object(const std::string& key,
                                const protocol::Bytes& plaintext) {
        if (key.size() != 16) {
            throw std::invalid_argument("AES keys must contain exactly 16 bytes");
        }
        const auto iv = secure_random_bytes(16);
        const auto ciphertext = AES(key).encrypt_cbc(plaintext, iv);
        auto object = iv;
        object.insert(object.end(), ciphertext.begin(), ciphertext.end());
        return object;
    }

    protocol::Bytes decrypt_object(const std::string& key,
                                const protocol::Bytes& object) {
        if (key.size() != 16 || object.size() < 32 ||
            (object.size() - 16) % 16 != 0) {
            throw std::invalid_argument("Malformed encrypted object");
        }
        const protocol::Bytes iv(object.begin(), object.begin() + 16);
        const protocol::Bytes ciphertext(object.begin() + 16, object.end());
        return AES(key).decrypt_cbc(ciphertext, iv);
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
            (packet.encrypted_object.size() - 16) % 16 != 0 ||
            !packet.tag.empty()) {
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
        return protocol::encode_message(protocol::MessageType::ChatMessage,
                                        writer.bytes());
    }

    protocol::Bytes encrypted_object_body(const protocol::Bytes& object) {
        return protocol::encode_message(
            protocol::MessageType::ChallengeResponse,
            protocol::encode_length_prefixed(object));
    }

    }

    Alice::Alice(std::string identity, std::string responder_identity,
                std::string long_term_key)
        : identity_(std::move(identity)),
        responder_identity_(std::move(responder_identity)),
        long_term_key_(std::move(long_term_key)) {
        if (!protocol::valid_id(identity_) || !protocol::valid_id(responder_identity_) ||
            identity_ == responder_identity_ || long_term_key_.size() != 16 ||
            !std::all_of(long_term_key_.begin(), long_term_key_.end(),
                        [](unsigned char value) { return value <= 0x7f; })) {
            throw std::invalid_argument(
                "Alice requires distinct valid identities and a 16-byte ASCII key");
        }
    }

    void Alice::run(const std::string& kdc_host, const std::string& kdc_port,
                    const std::string& bob_host, const std::string& bob_port) const {
        const auto nonce = secure_random_bytes(16);
        const protocol::KeyRequest request{identity_, responder_identity_, nonce};
        const auto request_message = protocol::encode_message(
            protocol::MessageType::KdcRequest, protocol::encode_key_request(request));

        auto kdc_connection = network::connect_tcp(kdc_host, kdc_port);
        kdc_connection.send_frame(request_message);
        const auto kdc_response_message = kdc_connection.receive_frame();

        protocol::Bytes response_body;
        const auto response_type =
            protocol::decode_message(kdc_response_message, response_body);
        if (response_type == protocol::MessageType::Error) {
            protocol::Reader error_reader(response_body);
            (void)error_reader.uint16();
            const auto message = error_reader.string_field();
            error_reader.require_done();
            throw std::runtime_error("KDC rejected the request: " + message);
        }
        if (response_type != protocol::MessageType::KdcResponse) {
            throw std::invalid_argument("Expected KDC_RESPONSE");
        }

        const auto response = protocol::decode_key_response(response_body);
        const auto alice_plaintext =
            decrypt_object(long_term_key_, response.encrypted_alice_part);
        protocol::Reader alice_reader(alice_plaintext);
        const auto session_key_bytes = alice_reader.fixed(16);
        const auto returned_alice_id = alice_reader.string_field();
        const auto returned_bob_id = alice_reader.string_field();
        const auto returned_nonce = alice_reader.fixed(16);
        alice_reader.require_done();
        if (returned_alice_id != identity_ ||
            returned_bob_id != responder_identity_ ||
            !same_bytes(returned_nonce, nonce)) {
            throw std::runtime_error("KDC response did not match Alice's request");
        }
        const std::string session_key(session_key_bytes.begin(), session_key_bytes.end());

        auto bob_connection = network::connect_tcp(bob_host, bob_port);
        bob_connection.send_frame(protocol::encode_message(
            protocol::MessageType::BobTicket,
            protocol::encode_length_prefixed(response.encrypted_bob_ticket)));

        protocol::Bytes challenge_body;
        if (protocol::decode_message(bob_connection.receive_frame(), challenge_body) !=
            protocol::MessageType::Challenge) {
            throw std::invalid_argument("Expected CHALLENGE from Bob");
        }
        const auto challenge_object = protocol::decode_length_prefixed(challenge_body);
        const auto challenge = decrypt_object(session_key, challenge_object);
        if (challenge.size() != 16) {
            throw std::invalid_argument("Bob's challenge must contain exactly 16 bytes");
        }
        bob_connection.send_frame(encrypted_object_body(
            encrypt_object(session_key, increment_nonce(challenge))));

        std::cout << "Authenticated with Bob " << responder_identity_
                << "; chat is confidentiality-only (no message authentication)\n"
                << "Enter ASCII messages; type /quit to disconnect.\n";

        std::atomic_bool receive_finished{false};
        std::thread receiver([&] {
            std::uint64_t expected_sequence = 0;
            try {
                while (!receive_finished.load()) {
                    const auto incoming = bob_connection.receive_frame();
                    protocol::Bytes body;
                    if (protocol::decode_message(incoming, body) !=
                        protocol::MessageType::ChatMessage) {
                        throw std::invalid_argument(
                            "Expected CHAT_MESSAGE after authentication");
                    }
                    const auto packet = decode_chat(body);
                    if (packet.sender != responder_identity_ ||
                        packet.sequence != expected_sequence) {
                        throw std::runtime_error(
                            "Invalid chat sender or sequence number");
                    }
                    const auto plaintext =
                        decrypt_object(session_key, packet.encrypted_object);
                    if (!is_ascii(plaintext)) {
                        throw std::runtime_error("Received chat message is not ASCII");
                    }
                    std::cout << responder_identity_ << ": "
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
                bob_connection.send_frame(encode_chat(
                    identity_, outgoing_sequence++,
                    encrypt_object(session_key, plaintext)));
            }
        } catch (...) {
            send_failure = std::current_exception();
        }
        receive_finished = true;
        bob_connection.shutdown();
        receiver.join();
        if (send_failure) {
            std::rethrow_exception(send_failure);
        }
    }
}