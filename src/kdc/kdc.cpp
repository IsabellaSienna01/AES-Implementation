#include "kdc/kdc.hpp"

#include "crypto/aes.hpp"
#include "common/secure_random.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <utility>

namespace sm::kdc {
namespace {

std::string to_compact_hex(const protocol::Bytes& bytes, std::size_t count) {
    static const char digits[] = "0123456789abcdef";
    std::string result;
    const std::size_t limit = std::min(count, bytes.size());
    for (std::size_t i = 0; i < limit; ++i) {
        result += digits[(bytes[i] >> 4) & 0x0f];
        result += digits[bytes[i] & 0x0f];
    }
    return result;
}

std::string to_hex_spaced(const protocol::Bytes& bytes) {
    static const char digits[] = "0123456789abcdef";
    std::string result;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0) result += ' ';
        result += digits[(bytes[i] >> 4) & 0x0f];
        result += digits[bytes[i] & 0x0f];
    }
    return result;
}

std::string to_token(const protocol::Bytes& bytes) {
    static const char table[] =
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ#$!*";
    std::string result;
    result.reserve(bytes.size());
    for (unsigned char b : bytes) {
        if (b >= 33 && b <= 126 && b != '\'' && b != '\\') {
            result += static_cast<char>(b);
        } else {
            result += table[b % (sizeof(table) - 1)];
        }
    }
    return result;
}

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

    const auto alice_encrypted = encrypt_object(alice_key->second, alice_plaintext.bytes());
    const auto bob_encrypted = encrypt_object(bob_key->second, bob_plaintext.bytes());

    const protocol::Bytes bob_iv(bob_encrypted.begin(), bob_encrypted.begin() + 16);
    const protocol::Bytes bob_cipher(bob_encrypted.begin() + 16, bob_encrypted.end());

    std::cout << "[KDC] [AUTH] Validating identities: Initiator='" << request.initiator_id
              << "', Responder='" << request.responder_id << "' -> [OK]\n"
              << "[KDC] [NONCE] Received Nonce N1: 0x" << to_compact_hex(request.nonce, 3) << "... (16 bytes)\n"
              << "[KDC] [CRYPTO] Generated fresh Session Key Ks:\n"
              << "      -> Raw Bytes (Hex): " << to_hex_spaced(session_key) << "\n"
              << "      -> ASCII / Token  : '" << to_token(session_key) << "'\n"
              << "[KDC] [CRYPTO] Encrypting ticket for Bob (Kb)... Done. (IV: 0x"
              << to_compact_hex(bob_iv, 1) << "..., Ciphertext: 0x"
              << to_compact_hex(bob_cipher, 1) << "...)\n"
              << "[KDC] [CRYPTO] Encrypting response for Alice (Ka)... Done." << std::endl;

    protocol::KeyResponse response{alice_encrypted, bob_encrypted};
    return protocol::encode_message(
        protocol::MessageType::KdcResponse, protocol::encode_key_response(response));
}

}
