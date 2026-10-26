#include "kdc/kdc.hpp"

#include "crypto/aes.hpp"
#include "common/secure_random.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace sm::kdc {
namespace {

protocol::Bytes encrypt_object(const std::string& key,
                               const protocol::Bytes& plaintext) {
    if (key.size() != 16) {
        throw std::invalid_argument("Long-term keys must contain exactly 16 ASCII bytes");
    }
    const auto iv = sm::secure_random_bytes(16);
    AES aes(key);
    const auto ciphertext = aes.encrypt_cbc(plaintext, iv);
    auto encrypted = iv;
    encrypted.insert(encrypted.end(), ciphertext.begin(), ciphertext.end());
    return encrypted;
}

}

Kdc::Kdc(std::map<std::string, std::string> long_term_keys)
    : long_term_keys_(std::move(long_term_keys)) {
    if (long_term_keys_.size() < 2) {
        throw std::invalid_argument("KDC requires keys for at least two identities");
    }
    for (const auto& [id, key] : long_term_keys_) {
        if (!protocol::valid_id(id) || key.size() != 16 ||
            !std::all_of(key.begin(), key.end(),
                         [](unsigned char value) { return value <= 0x7f; })) {
            throw std::invalid_argument(
                "KDC identities must be valid and keys exactly 16 ASCII bytes");
        }
    }
}

protocol::Bytes Kdc::process_request(const protocol::Bytes& payload) const {
    protocol::Bytes body;
    if (protocol::decode_message(payload, body) != protocol::MessageType::KdcRequest) {
        throw std::invalid_argument("KDC expected a KDC_REQUEST message");
    }
    const auto request = protocol::decode_key_request(body);
    const auto alice_key = long_term_keys_.find(request.initiator_id);
    const auto bob_key = long_term_keys_.find(request.responder_id);
    if (alice_key == long_term_keys_.end() || bob_key == long_term_keys_.end() ||
        request.initiator_id == request.responder_id) {
        throw std::invalid_argument("KDC request contains an unknown or invalid identity");
    }

    const auto session_key = sm::secure_random_bytes(16);
    protocol::Writer alice_plaintext;
    alice_plaintext.fixed(session_key);
    alice_plaintext.string_field(request.initiator_id);
    alice_plaintext.string_field(request.responder_id);
    alice_plaintext.fixed(request.nonce);

    protocol::Writer bob_plaintext;
    bob_plaintext.fixed(session_key);
    bob_plaintext.string_field(request.initiator_id);

    protocol::KeyResponse response{
        encrypt_object(alice_key->second, alice_plaintext.bytes()),
        encrypt_object(bob_key->second, bob_plaintext.bytes())
    };
    return protocol::encode_message(
        protocol::MessageType::KdcResponse, protocol::encode_key_response(response));
}

}
