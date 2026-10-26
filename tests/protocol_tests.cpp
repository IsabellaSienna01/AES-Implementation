#include "crypto/aes.hpp"
#include "kdc/kdc.hpp"
#include "protocol/messages.hpp"

#include <cassert>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>

namespace {

sm::protocol::Bytes decrypt_object(const std::string& key,
                                   const sm::protocol::Bytes& object) {
    assert(object.size() >= 32);
    const sm::protocol::Bytes iv(object.begin(), object.begin() + 16);
    const sm::protocol::Bytes ciphertext(object.begin() + 16, object.end());
    return AES(key).decrypt_cbc(ciphertext, iv);
}

void test_request_serialization() {
    using namespace sm::protocol;
    const KeyRequest request{"Alice_1", "Bob-2", Bytes(16, 0x5a)};
    const auto encoded = encode_message(MessageType::KdcRequest, encode_key_request(request));
    Bytes body;
    assert(decode_message(encoded, body) == MessageType::KdcRequest);
    const auto decoded = decode_key_request(body);
    assert(decoded.initiator_id == request.initiator_id);
    assert(decoded.responder_id == request.responder_id);
    assert(decoded.nonce == request.nonce);

    auto trailing_data = body;
    trailing_data.push_back(0);
    bool rejected_trailing = false;
    try {
        (void)decode_key_request(trailing_data);
    } catch (const std::invalid_argument&) {
        rejected_trailing = true;
    }
    assert(rejected_trailing);

    bool rejected_invalid_id = false;
    try {
        (void)encode_key_request(KeyRequest{"not valid", "Bob", Bytes(16)});
    } catch (const std::invalid_argument&) {
        rejected_invalid_id = true;
    }
    assert(rejected_invalid_id);
}

void test_kdc_distribution() {
    using namespace sm::protocol;
    const std::string alice_key = "AliceLongKey1234";
    const std::string bob_key = "BobLongKey123456";
    sm::kdc::Kdc kdc({{"Alice", alice_key}, {"Bob", bob_key}});
    const KeyRequest request{"Alice", "Bob", Bytes(16, 0x4c)};
    const auto request_message =
        encode_message(MessageType::KdcRequest, encode_key_request(request));
    const auto response_message = kdc.process_request(request_message);

    Bytes response_body;
    assert(decode_message(response_message, response_body) == MessageType::KdcResponse);
    const auto response = decode_key_response(response_body);

    const auto alice_plaintext = decrypt_object(alice_key, response.encrypted_alice_part);
    Reader alice_reader(alice_plaintext);
    const auto session_key = alice_reader.fixed(16);
    assert(alice_reader.string_field() == "Alice");
    assert(alice_reader.string_field() == "Bob");
    assert(alice_reader.fixed(16) == request.nonce);
    alice_reader.require_done();

    const auto bob_plaintext = decrypt_object(bob_key, response.encrypted_bob_ticket);
    Reader bob_reader(bob_plaintext);
    assert(bob_reader.fixed(16) == session_key);
    assert(bob_reader.string_field() == "Alice");
    bob_reader.require_done();

    bool rejected_wrong_alice_key = false;
    try {
        rejected_wrong_alice_key =
            decrypt_object("WrongAliceKey123", response.encrypted_alice_part) !=
            alice_plaintext;
    } catch (const std::invalid_argument&) {
        rejected_wrong_alice_key = true;
    }
    assert(rejected_wrong_alice_key);

    bool rejected_wrong_bob_key = false;
    try {
        rejected_wrong_bob_key =
            decrypt_object("BadBobKey1234567", response.encrypted_bob_ticket) !=
            bob_plaintext;
    } catch (const std::invalid_argument&) {
        rejected_wrong_bob_key = true;
    }
    assert(rejected_wrong_bob_key);

    bool rejected_unknown_id = false;
    try {
        const auto invalid = encode_message(
            MessageType::KdcRequest,
            encode_key_request(KeyRequest{"Alice", "Mallory", Bytes(16)}));
        (void)kdc.process_request(invalid);
    } catch (const std::invalid_argument&) {
        rejected_unknown_id = true;
    }
    assert(rejected_unknown_id);
}

void test_invalid_message_and_response() {
    using namespace sm::protocol;
    bool rejected_bad_version = false;
    try {
        Bytes malformed{0x02, static_cast<unsigned char>(MessageType::KdcRequest)};
        Bytes body;
        (void)decode_message(malformed, body);
    } catch (const std::invalid_argument&) {
        rejected_bad_version = true;
    }
    assert(rejected_bad_version);

    bool rejected_empty = false;
    try {
        (void)decode_key_request(Bytes{});
    } catch (const std::invalid_argument&) {
        rejected_empty = true;
    }
    assert(rejected_empty);

    bool rejected_truncated_payload = false;
    try {
        (void)decode_key_request(Bytes{0x01, 0x02});
    } catch (const std::invalid_argument&) {
        rejected_truncated_payload = true;
    }
    assert(rejected_truncated_payload);

    bool rejected_bad_encrypted_object = false;
    try {
        (void)decode_key_response(Bytes{0, 1, 1, 0, 1, 2});
    } catch (const std::invalid_argument&) {
        rejected_bad_encrypted_object = true;
    }
    assert(rejected_bad_encrypted_object);
}

}

int main() {
    test_request_serialization();
    test_kdc_distribution();
    test_invalid_message_and_response();
    std::cout << "KDC and protocol tests passed\n";
}
