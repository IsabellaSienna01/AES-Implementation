#include "protocol/messages.hpp"

#include <algorithm>
#include <stdexcept>

namespace sm::protocol {

bool valid_id(const std::string& id) {
    return !id.empty() && id.size() <= 32 &&
           std::all_of(id.begin(), id.end(), [](unsigned char c) {
               return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '_' || c == '-';
           });
}

void Writer::byte(unsigned char value) { bytes_.push_back(value); }

void Writer::uint16(std::uint16_t value) {
    bytes_.push_back(static_cast<unsigned char>((value >> 8) & 0xff));
    bytes_.push_back(static_cast<unsigned char>(value & 0xff));
}

void Writer::uint64(std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        bytes_.push_back(static_cast<unsigned char>((value >> shift) & 0xff));
    }
}

void Writer::fixed(const Bytes& value) {
    bytes_.insert(bytes_.end(), value.begin(), value.end());
}

void Writer::field(const Bytes& value) {
    if (value.size() > 0xffff) {
        throw std::invalid_argument("Field exceeds the wire-format limit");
    }
    uint16(static_cast<std::uint16_t>(value.size()));
    fixed(value);
}

void Writer::string_field(const std::string& value) {
    field(Bytes(value.begin(), value.end()));
}

const Bytes& Writer::bytes() const { return bytes_; }

Reader::Reader(const Bytes& bytes) : bytes_(bytes) {}

unsigned char Reader::byte() {
    if (offset_ >= bytes_.size()) {
        throw std::invalid_argument("Truncated protocol payload");
    }
    return bytes_[offset_++];
}

std::uint16_t Reader::uint16() {
    const auto high = byte();
    const auto low = byte();
    return static_cast<std::uint16_t>((high << 8) | low);
}

std::uint64_t Reader::uint64() {
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | byte();
    }
    return value;
}

Bytes Reader::fixed(std::size_t count) {
    if (count > bytes_.size() - offset_) {
        throw std::invalid_argument("Truncated protocol payload");
    }
    Bytes result(bytes_.begin() + static_cast<std::ptrdiff_t>(offset_),
                 bytes_.begin() + static_cast<std::ptrdiff_t>(offset_ + count));
    offset_ += count;
    return result;
}

Bytes Reader::field(std::size_t maximum) {
    const auto length = uint16();
    if (length > maximum) {
        throw std::invalid_argument("Protocol field exceeds its maximum length");
    }
    return fixed(length);
}

std::string Reader::string_field(std::size_t maximum) {
    const auto value = field(maximum);
    return std::string(value.begin(), value.end());
}

void Reader::require_done() const {
    if (offset_ != bytes_.size()) {
        throw std::invalid_argument("Trailing bytes in protocol payload");
    }
}

Bytes encode_message(MessageType type, const Bytes& body) {
    if (body.size() + 2 > MaxPayloadSize) {
        throw std::invalid_argument("Protocol payload exceeds 1 MiB");
    }
    Writer writer;
    writer.byte(Version);
    writer.byte(static_cast<unsigned char>(type));
    writer.fixed(body);
    return writer.bytes();
}

MessageType decode_message(const Bytes& payload, Bytes& body) {
    if (payload.size() < 4 || payload.size() > MaxPayloadSize) {
        throw std::invalid_argument("Invalid protocol payload size");
    }
    Reader reader(payload);
    if (reader.byte() != Version) {
        throw std::invalid_argument("Unsupported protocol version");
    }
    const auto type = static_cast<MessageType>(reader.byte());
    switch (type) {
    case MessageType::KdcRequest:
    case MessageType::KdcResponse:
    case MessageType::BobTicket:
    case MessageType::Challenge:
    case MessageType::ChallengeResponse:
    case MessageType::ChatMessage:
    case MessageType::Error:
        break;
    default:
        throw std::invalid_argument("Unsupported protocol message type");
    }
    
    uint16_t body_len = reader.uint16();
    
    body = reader.fixed(body_len);
    
    reader.require_done();
    return type;
}

Bytes encode_key_request(const KeyRequest& request) {
    if (!valid_id(request.initiator_id) || !valid_id(request.responder_id) ||
        request.nonce.size() != 16) {
        throw std::invalid_argument("Invalid KDC request fields");
    }
    Writer writer;
    writer.string_field(request.initiator_id);
    writer.string_field(request.responder_id);
    writer.fixed(request.nonce);
    return writer.bytes();
}

KeyRequest decode_key_request(const Bytes& body) {
    Reader reader(body);
    KeyRequest request{reader.string_field(), reader.string_field(), reader.fixed(16)};
    reader.require_done();
    if (!valid_id(request.initiator_id) || !valid_id(request.responder_id)) {
        throw std::invalid_argument("Invalid identity in KDC request");
    }
    return request;
}

Bytes encode_key_response(const KeyResponse& response) {
    Writer writer;
    writer.field(response.encrypted_alice_part);
    writer.field(response.encrypted_bob_ticket);
    return writer.bytes();
}

KeyResponse decode_key_response(const Bytes& body) {
    Reader reader(body);
    KeyResponse response{reader.field(), reader.field()};
    reader.require_done();
    if (response.encrypted_alice_part.size() < 32 ||
        response.encrypted_bob_ticket.size() < 32 ||
        (response.encrypted_alice_part.size() - 16) % 16 != 0 ||
        (response.encrypted_bob_ticket.size() - 16) % 16 != 0) {
        throw std::invalid_argument("Invalid encrypted object in KDC response");
    }
    return response;
}

Bytes encode_length_prefixed(const Bytes& field) {
    Writer writer;
    writer.field(field);
    return writer.bytes();
}

Bytes decode_length_prefixed(const Bytes& body) {
    Reader reader(body);
    auto field = reader.field();
    reader.require_done();
    return field;
}

}
