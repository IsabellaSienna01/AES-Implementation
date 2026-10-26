#include "network/tcp_connection.hpp"

#include <array>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace sm::network {
namespace {

#ifdef _WIN32
using socket_length_t = int;
void initialize_sockets() {
    static const bool initialized = [] {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            throw std::runtime_error("Winsock initialization failed");
        }
        return true;
    }();
    (void)initialized;
}
int last_socket_error() { return WSAGetLastError(); }
#else
using socket_length_t = socklen_t;
void initialize_sockets() {}
int last_socket_error() { return errno; }
#endif

void close_socket(sm_socket_t socket) noexcept {
#ifdef _WIN32
    closesocket(socket);
#else
    ::close(socket);
#endif
}

int send_bytes(sm_socket_t socket, const unsigned char* data, std::size_t size) {
#ifdef _WIN32
    return ::send(socket, reinterpret_cast<const char*>(data),
                  static_cast<int>(size), 0);
#else
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#endif
    return static_cast<int>(::send(socket, data, size, flags));
#endif
}

int receive_bytes(sm_socket_t socket, unsigned char* data, std::size_t size) {
#ifdef _WIN32
    return ::recv(socket, reinterpret_cast<char*>(data),
                  static_cast<int>(size), 0);
#else
    return static_cast<int>(::recv(socket, data, size, 0));
#endif
}

void transfer_all(sm_socket_t socket, const unsigned char* data, std::size_t size,
                  bool sending) {
    std::size_t transferred = 0;
    while (transferred < size) {
        const int result = sending
            ? send_bytes(socket, data + transferred, size - transferred)
            : receive_bytes(socket, const_cast<unsigned char*>(data + transferred),
                            size - transferred);
        if (result <= 0) {
            if (!sending && transferred == 0) {
                const int err = last_socket_error();
#ifdef _WIN32
                if (result == 0 || err == WSAECONNRESET || err == WSAECONNABORTED) {
                    throw ConnectionClosedException();
                }
#else
                if (result == 0 || err == ECONNRESET) {
                    throw ConnectionClosedException();
                }
#endif
            }
            throw std::runtime_error("TCP connection closed or operation failed (" +
                                     std::to_string(last_socket_error()) + ")");
        }
        transferred += static_cast<std::size_t>(result);
    }
}

TcpConnection resolve_socket(const std::string& host, const std::string& port,
                             bool listening) {
    initialize_sockets();
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = listening ? AI_PASSIVE : 0;
    addrinfo* addresses = nullptr;
    const char* node = host.empty() || host == "*" ? nullptr : host.c_str();
    const int lookup = getaddrinfo(node, port.c_str(), &hints, &addresses);
    if (lookup != 0) {
        throw std::runtime_error("Could not resolve TCP endpoint");
    }

    sm_socket_t selected = TcpConnection::invalid_socket();
    for (auto* address = addresses; address != nullptr; address = address->ai_next) {
        const auto candidate = ::socket(address->ai_family, address->ai_socktype,
                                        address->ai_protocol);
        if (candidate == TcpConnection::invalid_socket()) {
            continue;
        }
        if (listening) {
            int reuse = 1;
#ifdef _WIN32
            setsockopt(candidate, SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#else
            setsockopt(candidate, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif
            if (::bind(candidate, address->ai_addr,
                       static_cast<socket_length_t>(address->ai_addrlen)) == 0 &&
                ::listen(candidate, SOMAXCONN) == 0) {
                selected = candidate;
                break;
            }
        } else if (::connect(candidate, address->ai_addr,
                             static_cast<socket_length_t>(address->ai_addrlen)) == 0) {
            selected = candidate;
            break;
        }
        close_socket(candidate);
    }
    freeaddrinfo(addresses);
    if (selected == TcpConnection::invalid_socket()) {
        throw std::runtime_error("Could not open TCP endpoint (" +
                                 std::to_string(last_socket_error()) + ")");
    }
    return TcpConnection(selected);
}

}

TcpConnection::TcpConnection(sm_socket_t socket) : socket_(socket) {}
TcpConnection::~TcpConnection() { close(); }
TcpConnection::TcpConnection(TcpConnection&& other) noexcept : socket_(other.socket_) {
    other.socket_ = invalid_socket();
}
TcpConnection& TcpConnection::operator=(TcpConnection&& other) noexcept {
    if (this != &other) {
        close();
        socket_ = other.socket_;
        other.socket_ = invalid_socket();
    }
    return *this;
}

sm_socket_t TcpConnection::invalid_socket() {
#ifdef _WIN32
    return INVALID_SOCKET;
#else
    return -1;
#endif
}

bool TcpConnection::valid() const { return socket_ != invalid_socket(); }

void TcpConnection::close() noexcept {
    if (valid()) {
        close_socket(socket_);
        socket_ = invalid_socket();
    }
}

void TcpConnection::send_frame(const protocol::Bytes& payload) const {
    if (!valid() || payload.empty() || payload.size() > protocol::MaxPayloadSize) {
        throw std::invalid_argument("Invalid TCP frame");
    }
    const auto length = static_cast<std::uint32_t>(payload.size());
    std::array<unsigned char, 4> header{
        static_cast<unsigned char>(length >> 24),
        static_cast<unsigned char>(length >> 16),
        static_cast<unsigned char>(length >> 8),
        static_cast<unsigned char>(length)
    };
    transfer_all(socket_, header.data(), header.size(), true);
    transfer_all(socket_, payload.data(), payload.size(), true);
}

void TcpConnection::shutdown() const noexcept {
    if (valid()) {
#ifdef _WIN32
        ::shutdown(socket_, SD_BOTH);
#else
        ::shutdown(socket_, SHUT_RDWR);
#endif
    }
}

protocol::Bytes TcpConnection::receive_frame() const {
    if (!valid()) {
        throw std::invalid_argument("TCP connection is not open");
    }
    std::array<unsigned char, 4> header{};
    transfer_all(socket_, header.data(), header.size(), false);
    const std::uint32_t length =
        (static_cast<std::uint32_t>(header[0]) << 24) |
        (static_cast<std::uint32_t>(header[1]) << 16) |
        (static_cast<std::uint32_t>(header[2]) << 8) |
        static_cast<std::uint32_t>(header[3]);
    if (length == 0 || length > protocol::MaxPayloadSize) {
        throw std::invalid_argument("Invalid TCP frame length");
    }
    protocol::Bytes payload(length);
    transfer_all(socket_, payload.data(), payload.size(), false);
    return payload;
}

std::string TcpConnection::peer_address() const {
    if (!valid()) {
        return "unknown";
    }
    sockaddr_storage addr{};
    socket_length_t len = sizeof(addr);
    if (::getpeername(socket_, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
        return "unknown";
    }
    char ip[INET6_ADDRSTRLEN]{};
    int port = 0;
    if (addr.ss_family == AF_INET) {
        const auto* s = reinterpret_cast<const sockaddr_in*>(&addr);
        inet_ntop(AF_INET, const_cast<in_addr*>(&s->sin_addr), ip, sizeof(ip));
        port = ntohs(s->sin_port);
    } else if (addr.ss_family == AF_INET6) {
        const auto* s = reinterpret_cast<const sockaddr_in6*>(&addr);
        inet_ntop(AF_INET6, const_cast<in6_addr*>(&s->sin6_addr), ip, sizeof(ip));
        port = ntohs(s->sin6_port);
    } else {
        return "unknown";
    }
    return std::string(ip) + ":" + std::to_string(port);
}

TcpConnection connect_tcp(const std::string& host, const std::string& port) {
    return resolve_socket(host, port, false);
}

TcpConnection create_tcp_listener(const std::string& host, const std::string& port) {
    return resolve_socket(host, port, true);
}

TcpConnection accept_tcp(const TcpConnection& listener) {
    if (!listener.valid()) {
        throw std::invalid_argument("TCP listener is not open");
    }
    initialize_sockets();
    const auto accepted = ::accept(listener.socket_, nullptr, nullptr);
    if (accepted == TcpConnection::invalid_socket()) {
        throw std::runtime_error("TCP accept failed (" +
                                 std::to_string(last_socket_error()) + ")");
    }
    return TcpConnection(accepted);
}

}
