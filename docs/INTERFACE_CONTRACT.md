# Interface Contract — Secure Messaging

**Status:** Draft v1.0  
**Language/build:** C++20 + CMake  
**Entities:** KDC, Alice, Bob  
**Transport:** TCP over three distinct reachable IP addresses  
**Cryptography:** manually implemented AES-128; no crypto library may replace the required AES/KDC logic

## 1. Shared decisions

These decisions are the source of truth for both contributors. Change them only by agreement and update this document and tests in the same commit.

- AES variant: AES-128, 16-byte key and 16-byte block.
- Key input: exactly 16 ASCII bytes for each long-term key and session key. Reject invalid length; do not silently truncate or pad keys.
- IDs: UTF-8/ASCII identifiers restricted in v1 to `[A-Za-z0-9_-]{1,32}`.
- Nonces: 16 bytes from an operating-system cryptographically secure random source. Do not use `rand()` for nonces or keys.
- Wire encoding: binary, big-endian integer fields, length-prefixed messages. Do not send C++ structs directly over the network.
- Display encoding: plaintext/key inputs are ASCII; ciphertext is displayed as lowercase hexadecimal, two hex characters per byte. Hex is a display/diagnostic representation, not the internal ciphertext representation.
- TCP framing: 4-byte unsigned payload length in network byte order, followed by exactly that many payload bytes. Maximum payload is 1 MiB. Reject zero-length payloads unless the message type explicitly permits them; reject lengths over the maximum.
- The receiver must loop until the full header and full payload are read. One `send()` is not guaranteed to correspond to one `recv()`.
- Do not log Ka, Kb, Ks, raw plaintext, or full decrypted protocol payloads.
- Error handling must be explicit. Invalid input, malformed frame, invalid message type, authentication failure, and network failure must not be treated as success.

## 2. Module ownership

### Contributor A
- `crypto/AES128`: AES-128 key expansion, block encrypt/decrypt, and tests against published AES test vectors.
- Alice initiator/client and Alice-side protocol state machine.
- Alice-side integration tests.

### Contributor B
- KDC key distribution logic and KDC server.
- Bob responder/server and Bob-side protocol state machine.
- TCP connection/framing implementation and network configuration.
- KDC/Bob/network tests.

### Shared
- This contract, protocol serialization, CMake integration, end-to-end tests, README, and demonstration.
- Shared headers may not be changed unilaterally.

## 3. Suggested public types

Use fixed-width bytes and byte vectors for cryptographic data. Avoid passing hex strings into cryptographic primitives.

```cpp
#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace sm {
using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;
using Block = std::array<Byte, 16>;
using AES128Key = std::array<Byte, 16>;

struct Endpoint {
    std::string host;
    std::uint16_t port{};
};

struct KeyRequest {
    std::string initiator_id;
    std::string responder_id;
    Bytes nonce; // exactly 16 bytes
};

struct KeyResponse {
    Bytes encrypted_alice_part;
    Bytes encrypted_bob_ticket;
};

struct ChatMessage {
    std::string sender_id;
    std::uint64_t sequence_number{};
    Bytes iv;                  // 16 bytes for CBC
    Bytes ciphertext;          // block-aligned for CBC
    Bytes authentication_tag;  // 32 bytes if HMAC-SHA-256 is implemented
};
}
```

This is a logical API proposal, not a wire format. The wire format is defined in `PROTOCOL.md`. Do not serialize these C++ structs by copying their memory layout.

## 4. AES API contract

The AES module should expose a block primitive similar to:

```cpp
namespace sm::crypto {
class AES128 {
public:
    explicit AES128(const AES128Key& key);
    Block encrypt_block(const Block& input) const;
    Block decrypt_block(const Block& input) const;
};
}
```

Requirements:
- `encrypt_block` and `decrypt_block` operate on exactly one 16-byte block.
- AES module does not perform networking, console I/O, hex conversion, padding, or protocol serialization.
- Validate AES correctness against known-answer test vectors, not only encrypt-then-decrypt round trips.
- Higher-level message encryption must be a separate module/API.

## 5. Message encryption profile

For the course implementation, the required primitive is manual AES-128. Agree with the instructor whether supporting components must also be manual.

Recommended minimum profile for arbitrary-length messages:
- AES-128-CBC with PKCS#7 padding and a fresh, unpredictable 16-byte IV per message.
- CBC does **not** provide integrity/authentication. For tamper detection, add HMAC-SHA-256 over a canonical encoding of the header, IV, and ciphertext, and verify it before decryption. If HMAC is out of scope, explicitly label the demo as confidentiality-only and do not claim tamper resistance.
- Never reuse an IV with the same key.
- Implement padding validation strictly. Invalid padding must be an error, not a partial plaintext.
- A fixed 16-character ASCII key is accepted as 16 raw bytes; do not silently interpret it as hexadecimal.

The exact profile must be agreed before implementing encrypted protocol messages. The protocol document assumes CBC + PKCS#7 for the draft profile.

## 6. Serialization contract

Each protocol payload is a sequence of fields encoded in the order stated in `PROTOCOL.md`. Variable-length byte/string fields use a 2-byte unsigned big-endian length followed by the bytes, unless the protocol specifies a fixed size. Reject a field if its length exceeds the documented limit or if trailing bytes remain after parsing.

- IDs: 1–32 bytes.
- Nonce: exactly 16 bytes.
- AES-128 key: exactly 16 bytes.
- IV: exactly 16 bytes.
- Ciphertext: 16 bytes minimum and a multiple of 16 for CBC with PKCS#7.
- Message payload maximum: 1 MiB.
- Ciphertext display: lowercase hex; decoder rejects odd length and non-hex characters.

## 7. State machine contract

Alice:
`Disconnected -> ConnectedToKDC -> AwaitingKDCResponse -> TicketReady -> AwaitingChallenge -> Authenticated -> Chatting`

Bob:
`Listening -> TicketReceived -> TicketValidated -> ChallengeSent -> Authenticated -> Chatting`

KDC:
`Listening -> RequestValidated -> SessionKeyCreated -> ResponseSent`

Only `Authenticated` endpoints may process `CHAT_MESSAGE`. Any unexpected message for the current state is rejected. A failed authentication resets or closes the session.

## 8. Error model

Use exceptions only for unrecoverable initialization failures if the team agrees. For normal protocol operations, prefer an explicit result/error type. Minimum error categories:

- `InvalidArgument`
- `InvalidFrame`
- `UnsupportedMessageType`
- `ProtocolStateError`
- `CryptoError`
- `AuthenticationFailed`
- `NetworkError`
- `Timeout`

Do not continue the protocol after a cryptographic or authentication error.

## 9. Definition of done

A module is ready to merge when it:
1. Builds under the shared CMake configuration.
2. Follows these public interfaces and serialization rules.
3. Has relevant unit tests.
4. Does not contain duplicate/conflicting protocol definitions.
5. Handles malformed input and errors deterministically.
6. Does not log secret keys or sensitive plaintext.
