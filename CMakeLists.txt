cmake_minimum_required(VERSION 3.20)

project(SecureMessaging
    VERSION 0.1.0
    DESCRIPTION "Coursework implementation of KDC key distribution and AES messaging"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SECURE_MESSAGING_BUILD_TESTS "Build unit/integration tests" ON)

# Shared protocol, framing, and operating-system utilities.
add_library(sm_common
    src/common/secure_random.cpp
    src/common/serialization.cpp
    src/network/tcp_connection.cpp
)
target_include_directories(sm_common PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_compile_features(sm_common PUBLIC cxx_std_20)
find_package(Threads REQUIRED)
target_link_libraries(sm_common PUBLIC Threads::Threads)
if(WIN32)
    target_link_libraries(sm_common PUBLIC ws2_32 bcrypt)
endif()

# Keep the AES implementation as a separate library so KDC/Alice/Bob share
# the same manual AES code and do not create duplicate implementations.
add_library(sm_crypto src/crypto/aes.cpp)
target_link_libraries(sm_crypto PUBLIC sm_common)

add_executable(kdc src/kdc/main.cpp)
add_library(kdc_core src/kdc/kdc.cpp)
target_link_libraries(kdc_core PUBLIC sm_common sm_crypto)
target_link_libraries(kdc PRIVATE kdc_core)

add_executable(bob src/bob/main.cpp)
add_library(bob_core src/bob/bob.cpp)
target_link_libraries(bob_core PUBLIC sm_common sm_crypto)
target_link_libraries(bob PRIVATE bob_core)

add_executable(alice
    src/alice/main.cpp
    src/alice/alice.cpp
    include/alice/alice.hpp
)
target_include_directories(alice PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include/alice"
)
target_link_libraries(alice PRIVATE sm_common sm_crypto)

if(MSVC)
    foreach(target kdc kdc_core bob bob_core alice sm_common)
        target_compile_options(${target} PRIVATE /W4 /permissive-)
    endforeach()
    if(TARGET sm_crypto)
        target_compile_options(sm_crypto PRIVATE /W4 /permissive-)
    endif()
else()
    foreach(target kdc kdc_core bob bob_core alice sm_common)
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endforeach()
    if(TARGET sm_crypto)
        target_compile_options(sm_crypto PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endif()

if(SECURE_MESSAGING_BUILD_TESTS)
    enable_testing()
    add_executable(aes_tests tests/aes_tests.cpp)
    target_link_libraries(aes_tests PRIVATE sm_crypto)
    add_test(NAME aes_tests COMMAND aes_tests)

    add_executable(protocol_tests tests/protocol_tests.cpp)
    target_link_libraries(protocol_tests PRIVATE kdc_core)
    add_test(NAME protocol_tests COMMAND protocol_tests)
endif()
