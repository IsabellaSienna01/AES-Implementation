#include "bob/bob.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

int main(int argc, char** argv) {
    try {
        if (argc != 5) {
            throw std::invalid_argument(
                "Usage: bob <bind-host> <port> <identity> <16-byte-long-term-key>");
        }
        sm::bob::Bob bob(argv[3], argv[4]);
        bob.run(argv[1], argv[2]);
    } catch (const std::exception& error) {
        std::cerr << "Bob startup failed: " << error.what() << '\n';
        return 1;
    }
}
