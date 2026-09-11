#include <P2p/P2pTransport.h>
#include <System/Context.h>
#include <System/TcpConnector.h>
#include <System/TcpListener.h>
#include <algorithm>
#include <array>
#include <chrono>
#include "p2p_transport/ProcessCpuTime.h"
#include <iostream>
#include <stdexcept>

using namespace CryptoNote;
using namespace System;
using Clock = std::chrono::steady_clock;
namespace {
double ms(Clock::time_point start) { return std::chrono::duration<double, std::milli>(Clock::now() - start).count(); }
void check(bool ok) { if (!ok) throw std::runtime_error("Transport benchmark data mismatch"); }
}

int main(int argc, char** argv) {
  try {
    const bool secure = argc > 1 && std::string(argv[1]) == "pq";
    const size_t total = (argc > 2 ? std::stoull(argv[2]) : 64) * 1024 * 1024;
    check(total >= 16384 && total % 16384 == 0);
    Dispatcher dispatcher;
    TcpListener listener(dispatcher, Ipv4Address("127.0.0.1"), 0);
    const auto port = listener.getLocalPort();
    P2pTransportConfig config;
    config.mode = secure ? P2pTransportMode::Required : P2pTransportMode::Off;
    P2pTransportContext profile(config, boost::uuids::uuid{});
    const auto start = Clock::now();
    P2pTransport client(dispatcher, TcpConnector(dispatcher).connect(Ipv4Address("127.0.0.1"), port));
    P2pTransport server(dispatcher, listener.accept());
    Context<> accept(dispatcher, [&] { server.startServer(profile); });
    if (secure) client.startClient(profile, "127.0.0.1:" + std::to_string(port)); else client.startLegacy();
    accept.get();
    const auto handshakeMs = ms(start);
    std::array<uint8_t, 16384> payload{};
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<uint8_t>(i);
    const auto cpu = P2pTransportTest::processCpuSeconds();
    const auto transfer = Clock::now();
    Context<> reader(dispatcher, [&] {
      std::array<uint8_t, 16384> buffer{};
      size_t received = 0;
      while (received < total) {
        const auto n = server.read(buffer.data(), buffer.size());
        check(n != 0);
        for (size_t i = 0; i < n; ++i) check(buffer[i] == static_cast<uint8_t>(received + i));
        received += n;
      }
      const uint8_t done = 1; server.write(&done, 1);
    });
    for (size_t sent = 0; sent < total;) sent += client.write(payload.data(), std::min(payload.size(), total - sent));
    uint8_t done = 0; check(client.read(&done, 1) == 1 && done == 1);
    reader.get();
    const auto transferMs = ms(transfer);
    const auto cpuSeconds = P2pTransportTest::processCpuSeconds() - cpu;
    const auto clientInfo = client.diagnostics(), serverInfo = server.diagnostics();
    if (secure && total > (uint64_t{1} << 30)) check(clientInfo.sentKeyUpdates != 0 && serverInfo.receivedKeyUpdates != 0);
    std::cout << "{\"mode\":\"" << (secure ? "pq" : "off") << "\",\"handshake_ms\":" << handshakeMs
      << ",\"bytes\":" << total << ",\"transfer_ms\":" << transferMs << ",\"cpu_seconds\":" << cpuSeconds
      << ",\"mib_per_second\":" << (total / 1048576.0) / (transferMs / 1000)
      << ",\"cipher\":\"" << clientInfo.cipher << "\",\"handshake_wire_bytes\":" << clientInfo.handshakeSent + serverInfo.handshakeSent
      << ",\"sent_key_updates\":" << clientInfo.sentKeyUpdates << ",\"received_key_updates\":" << serverInfo.receivedKeyUpdates << ",\"passed\":true}\n";
    return 0;
  } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
