#pragma once

#include "protocol/messages.hpp"

#include <stdexcept>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using sm_socket_t = SOCKET;
#else
using sm_socket_t = int;
#endif

namespace sm::network {

class ConnectionClosedException : public std::runtime_error {
public:
    ConnectionClosedException() : std::runtime_error("Connection closed by peer") {}
};

class TcpConnection {
public:
    explicit TcpConnection(sm_socket_t socket = invalid_socket());
    ~TcpConnection();
    TcpConnection(const TcpConnection&) = delete;
    TcpConnection& operator=(const TcpConnection&) = delete;
    TcpConnection(TcpConnection&& other) noexcept;
    TcpConnection& operator=(TcpConnection&& other) noexcept;

    static sm_socket_t invalid_socket();
    bool valid() const;
    void send_frame(const protocol::Bytes& payload) const;
    protocol::Bytes receive_frame() const;
    void shutdown() const noexcept;
    std::string peer_address() const;

private:
    sm_socket_t socket_;
    void close() noexcept;
    friend TcpConnection accept_tcp(const TcpConnection& listener);
};

TcpConnection connect_tcp(const std::string& host, const std::string& port);
TcpConnection create_tcp_listener(const std::string& host, const std::string& port);
TcpConnection accept_tcp(const TcpConnection& listener);

}

