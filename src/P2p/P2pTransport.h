#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <boost/uuid/uuid.hpp>
#include <System/TcpConnection.h>
#include <System/Ipv4Address.h>

namespace CryptoNote {

enum class P2pTransportMode { Off, Mixed, Required };

struct P2pTransportPin {
  std::string name;
  std::array<uint8_t, 32> sha256{};
};

struct P2pTransportConfig {
  P2pTransportMode mode = P2pTransportMode::Off;
  std::string keyFile;
  std::string name;
  // Canonical numeric IPv4:port, after name resolution, for every dial source.
  std::map<std::string, P2pTransportPin> pins;
  std::vector<std::string> requiredPeers;

  static P2pTransportMode parseMode(const std::string& value);
  static std::string endpoint(const std::string& ip, uint16_t port);
  static bool validName(const std::string& value);
  static P2pTransportPin parsePin(const std::string& value, std::string& endpoint);
  void validate() const;
  bool requiresPq(const std::string& endpoint) const;
  bool permitsFallback(const std::string& endpoint, bool inheritedPq) const;
};

class P2pTransportContext {
public:
  P2pTransportContext(P2pTransportConfig config, const boost::uuids::uuid& network);
  ~P2pTransportContext();
  P2pTransportContext(const P2pTransportContext&) = delete;
  P2pTransportContext& operator=(const P2pTransportContext&) = delete;
  const P2pTransportConfig& config() const;
  const std::string& alpn() const;
  std::string publicKeyFingerprint() const;
  static std::string networkAlpn(const boost::uuids::uuid& network);
  static bool supported();

  // Admission is synchronous on the dispatcher thread. No unbounded wait queue.
  bool admit(uint32_t ip, bool incoming);
  void release(uint32_t ip, bool incoming);
  static constexpr size_t MAX_INCOMING_HANDSHAKES = 16;
  static constexpr size_t MAX_OUTGOING_HANDSHAKES = 4;
  static constexpr size_t MAX_HANDSHAKES_PER_IP = 4;
  static constexpr uint32_t HANDSHAKE_TIMEOUT_MS = 5000;

private:
  friend class P2pTransport;
  struct Impl;
  std::shared_ptr<Impl> impl;
};

// A move transfers a handle, never a live SSL object or a socket reference.
// All operations and their handlers run on one System::Dispatcher thread.
class P2pTransport {
public:
  struct Diagnostics {
    std::string cipher;
    size_t handshakeReceived = 0, handshakeSent = 0;
    uint64_t sentKeyUpdates = 0, receivedKeyUpdates = 0;
  };
  P2pTransport(System::Dispatcher& dispatcher, System::TcpConnection&& connection);
  P2pTransport(P2pTransport&&) noexcept;
  P2pTransport& operator=(P2pTransport&&) noexcept;
  ~P2pTransport();
  P2pTransport(const P2pTransport&) = delete;
  P2pTransport& operator=(const P2pTransport&) = delete;

  void startLegacy();
  void startClient(P2pTransportContext& context, const std::string& endpoint);
  void startServer(P2pTransportContext& context);
  size_t read(uint8_t* data, size_t size);
  size_t write(const uint8_t* data, size_t size);
  void close() noexcept;
  bool secure() const;
  bool pinned() const;
  bool ready() const;
  Diagnostics diagnostics() const;
  std::pair<System::Ipv4Address, uint16_t> getPeerAddressAndPort() const;

private:
  struct Impl;
  std::shared_ptr<Impl> impl;
};

} // namespace CryptoNote
