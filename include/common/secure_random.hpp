#pragma once

#include <cstddef>
#include <vector>

namespace sm {

std::vector<unsigned char> secure_random_bytes(std::size_t count);

}
