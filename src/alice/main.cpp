#include "alice.hpp"

#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>

int main(int argc, char** argv) {
    try {
        if (argc != 8) {
            throw std::invalid_argument(
                "Usage: alice <kdc-host> <kdc-port> <bob-host> <bob-port> "
                "<alice-id> <bob-id> <16-byte-alice-key>");
        }

        sm::alice::Alice alice(argv[5], argv[6], argv[7]);
        alice.run(argv[1], argv[2], argv[3], argv[4]);
    } catch (const std::exception& error) {
        std::cerr << "Alice failed: " << error.what() << '\n';
        return 1;
    }
}