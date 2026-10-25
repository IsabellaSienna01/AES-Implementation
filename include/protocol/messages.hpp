#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sm::protocol {

using Bytes = std::vector<unsigned char>;

inline constexpr unsigned char Version = 0x01;
inline constexpr std::size_t MaxPayloadSize = 1024 * 1024;

enum class MessageType : unsigned char {
    KdcRequest = 0x01,
    KdcResponse = 0x02,
    BobTicket = 0x03,
    Challenge = 0x04,
    ChallengeResponse = 0x05,
    ChatMessage = 0x06,
    Error = 0x7f
};

struct KeyRequest {
    std::string initiator_id;
    std::string responder_id;
    Bytes nonce;
};

struct KeyResponse {
    Bytes encrypted_alice_part;
    Bytes encrypted_bob_ticket;
};

bool valid_id(const std::string& id);
Bytes encode_message(MessageType type, const Bytes& body);
MessageType decode_message(const Bytes& payload, Bytes& body);
Bytes encode_key_request(const KeyRequest& request);
KeyRequest decode_key_request(const Bytes& body);
Bytes encode_key_response(const KeyResponse& response);
KeyResponse decode_key_response(const Bytes& body);
Bytes encode_length_prefixed(const Bytes& field);
Bytes decode_length_prefixed(const Bytes& body);

class Writer {
public:
    void byte(unsigned char value);
    void uint16(std::uint16_t value);
    void uint64(std::uint64_t value);
    void fixed(const Bytes& value);
    void field(const Bytes& value);
    void string_field(const std::string& value);
    const Bytes& bytes() const;

private:
    Bytes bytes_;
};

class Reader {
public:
    explicit Reader(const Bytes& bytes);
    unsigned char byte();
    std::uint16_t uint16();
    std::uint64_t uint64();
    Bytes fixed(std::size_t count);
    Bytes field(std::size_t maximum = MaxPayloadSize);
    std::string string_field(std::size_t maximum = 32);
    void require_done() const;

private:
    const Bytes& bytes_;
    std::size_t offset_{};
};

}
