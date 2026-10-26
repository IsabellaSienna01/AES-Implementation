# AES Secure Messaging Project

This repository contains a C++20 coursework implementation of secure end-to-end messaging using a manually implemented AES-128 cipher, a Key Distribution Center (KDC), and a simple TCP-based protocol between Alice, Bob, and the KDC.

The project is designed to demonstrate the core flow of a Needham–Schroeder-style key exchange:

- Alice requests a session key from the KDC.
- KDC issues encrypted material for Alice and Bob.
- Alice forwards Bob's encrypted ticket.
- Bob challenges Alice using a session key.
- Alice and Bob authenticate and exchange encrypted application messages.

The implementation includes:

- Manual AES key expansion and encryption/decryption
- Secure random generation utilities
- TCP framing and socket utilities
- KDC session-key distribution logic
- Alice and Bob client/server flow
- Unit tests for AES and protocol behavior

## Project structure

```text
.
├── CMakeLists.txt
├── README.md
├── docs/
│   ├── INTERFACE_CONTRACT.md
│   ├── PROJECT_CONTRACT.md
│   └── PROTOCOL.md
├── include/
│   ├── alice/
│   ├── bob/
│   ├── common/
│   ├── crypto/
│   ├── kdc/
│   ├── network/
│   └── protocol/
├── src/
│   ├── alice/
│   ├── bob/
│   ├── common/
│   ├── crypto/
│   ├── kdc/
│   └── network/
├── tests/
│   ├── aes_tests.cpp
│   └── protocol_tests.cpp
├── build/
├── build-ninja/
└── ...
```

## Requirements

To build this project, you need:

- CMake 3.20 or newer
- A C++20 compiler
- Ninja or Makefiles (Ninja is recommended on Windows)

This project was validated with:

- CMake: 3.20+
- Compiler: GCC via MinGW
- Generator: Ninja

## Build instructions

From the repository root:

```bash
cmake -S . -B build-ninja -G Ninja -DSECURE_MESSAGING_BUILD_TESTS=ON
cmake --build build-ninja
```

You can also use a standard build directory instead of `build-ninja`:

```bash
cmake -S . -B build -DSECURE_MESSAGING_BUILD_TESTS=ON
cmake --build build
```

If you are using a Visual Studio toolchain and want to generate MSVC project files, run CMake with the default generator or a Visual Studio generator. If you are using MinGW/GCC on Windows, the Ninja generator is the simplest choice.

## Run tests

After building, run:

```bash
ctest --test-dir build-ninja --output-on-failure
```

or:

```bash
ctest --test-dir build --output-on-failure
```

This runs the AES and protocol test suites.

## How to run the demo

The project expects three separate processes: `KDC`, `Bob`, and `Alice`.

Important: the long-term keys shared between Alice and KDC, and between Bob and KDC, must be configured at runtime and must each be exactly 16 ASCII bytes. The example below uses 16-character strings so the binaries can be started locally without modifying source code.

### 1) Start the KDC

Open a terminal in the project root and run:

```powershell
.\build-ninja\kdc.exe 127.0.0.1 5000 --key alice=AliceKey12345678 --key bob=BobKey1234567890
```

This starts the KDC on `127.0.0.1:5000` and registers the Alice/Bob shared keys.

### 2) Start Bob

Open a second terminal and run:

```powershell
.\build-ninja\bob.exe 127.0.0.1 5001 bob BobKey1234567890
```

This starts Bob listening on `127.0.0.1:5001` for Alice's connection and uses Bob's long-term key.

### 3) Start Alice

Open a third terminal and run:

```powershell
.\build-ninja\alice.exe 127.0.0.1 5000 127.0.0.1 5001 alice bob AliceKey12345678
```

This tells Alice to:

- contact the KDC at `127.0.0.1:5000`
- connect to Bob at `127.0.0.1:5001`
- use the identity `alice` for the KDC request
- use the identity `bob` as the peer
- use Alice's long-term key for KDC authentication

Alice will request a session key, forward Bob's ticket, complete the challenge-response handshake, and then participate in the secure message flow.

## Build status

The project currently builds successfully with the Ninja generator and passes both test suites:

- `aes_tests`
- `protocol_tests`

A successful local validation command was:

```bash
cmake -S . -B build-ninja -G Ninja -DSECURE_MESSAGING_BUILD_TESTS=ON
cmake --build build-ninja
ctest --test-dir build-ninja --output-on-failure
```

This project is meant to be compiled and run as separate processes to observe the KDC/Alice/Bob communication flow end-to-end.
