#include "common/secure_random.hpp"

#include <stdexcept>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <cerrno>
#include <fstream>
#endif

namespace sm {

std::vector<unsigned char> secure_random_bytes(std::size_t count) {
    std::vector<unsigned char> bytes(count);
    if (count == 0) {
        return bytes;
    }

#ifdef _WIN32
    if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        throw std::runtime_error("Operating-system random number generation failed");
    }
#else
    std::ifstream random_source("/dev/urandom", std::ios::binary);
    if (!random_source ||
        !random_source.read(reinterpret_cast<char*>(bytes.data()),
                            static_cast<std::streamsize>(bytes.size()))) {
        throw std::runtime_error("Operating-system random number generation failed");
    }
#endif
    return bytes;
}

}
