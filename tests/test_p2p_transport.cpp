#include <gtest/gtest.h>
#include <P2p/P2pTransport.h>
#include <P2p/P2pTransportKey.h>
#include <P2p/LevinProtocol.h>
#include <System/Context.h>
#include <System/TcpConnector.h>
#include <System/TcpListener.h>
#include <System/Timer.h>
#include <filesystem>
#include <numeric>
#include <thread>
#include <fstream>
#include "p2p_transport/ProcessCpuTime.h"
#ifndef _WIN32
#include <unistd.h>
#include <sys/stat.h>
#endif
#if defined(DISCRETE_PQ_P2P)
#include <boost/asio/ssl.hpp>
#ifdef _WIN32
#include <aclapi.h>
#endif
#endif

using namespace CryptoNote;
using namespace System;
namespace {
P2pTransportConfig required() { P2pTransportConfig c; c.mode = P2pTransportMode::Required; return c; }
boost::uuids::uuid network() { boost::uuids::uuid n{}; std::iota(n.begin(), n.end(), uint8_t{0}); return n; }
size_t residentBytes() {
#if defined(__linux__)
  std::ifstream input("/proc/self/statm");
  size_t virtualPages = 0, residentPages = 0;
  if (!(input >> virtualPages >> residentPages)) throw std::runtime_error("Cannot measure fixture RSS");
  return residentPages * static_cast<size_t>(::sysconf(_SC_PAGESIZE));
#else
  return 0; // RSS gates are measured on the Linux qualification host.
#endif
}
const std::string endpoint = "127.0.0.1:39180";
}

TEST(P2pTransportPolicy, NetworkEncodingAndLocalFloors) {
  EXPECT_EQ("discrete-p2p/1/000102030405060708090a0b0c0d0e0f", P2pTransportContext::networkAlpn(network()));
  P2pTransportConfig config; config.mode = P2pTransportMode::Mixed;
  EXPECT_TRUE(config.permitsFallback(endpoint, false));
  EXPECT_FALSE(config.permitsFallback(endpoint, true));
  config.requiredPeers.push_back(endpoint);
  EXPECT_FALSE(config.permitsFallback(endpoint, false));
  config.mode = P2pTransportMode::Off;
  EXPECT_THROW(config.validate(), std::invalid_argument);
  EXPECT_THROW(P2pTransportConfig::parseMode("prefer"), std::invalid_argument);
  std::string ep;
  EXPECT_THROW(P2pTransportConfig::parsePin("127.0.0.1:0,a.invalid," + std::string(64, '0'), ep), std::invalid_argument);
  EXPECT_THROW(P2pTransportConfig::parsePin(endpoint + ",A.invalid," + std::string(64, '0'), ep), std::invalid_argument);
  EXPECT_FALSE(P2pTransportConfig::validName("-node.invalid"));
  EXPECT_FALSE(P2pTransportConfig::validName("node.invalid."));
  EXPECT_FALSE(P2pTransportConfig::validName("node..invalid"));
}

TEST(P2pTransportPolicy, AdmissionReservesOutgoingCapacityAndReleases) {
  P2pTransportContext p(P2pTransportConfig{}, network());
  for (size_t i = 0; i < P2pTransportContext::MAX_INCOMING_HANDSHAKES; ++i) EXPECT_TRUE(p.admit(static_cast<uint32_t>(i), true));
  EXPECT_FALSE(p.admit(999, true)); EXPECT_TRUE(p.admit(999, false));
  p.release(0, true); EXPECT_TRUE(p.admit(999, true));
  for (size_t i = 1; i < P2pTransportContext::MAX_HANDSHAKES_PER_IP; ++i) EXPECT_TRUE(p.admit(999, false));
  EXPECT_FALSE(p.admit(999, false));
  for (size_t i = 0; i < P2pTransportContext::MAX_HANDSHAKES_PER_IP; ++i) p.release(999, false);
  EXPECT_TRUE(p.admit(999, false));
}

#if defined(DISCRETE_PQ_P2P)
// Interrupt even a pre-TLS accept if a fixture cannot make progress. The timer
// owns no connection and is destroyed before its dispatcher.
struct FixtureDeadline {
  boost::asio::steady_timer timer;
  explicit FixtureDeadline(Dispatcher& dispatcher, std::chrono::milliseconds duration = std::chrono::seconds(20))
    : timer(dispatcher.getIoContext(), duration) {
    auto* waiting = dispatcher.getCurrentContext();
    timer.async_wait([&dispatcher, waiting](const boost::system::error_code& error) {
      if (!error) dispatcher.interrupt(waiting);
    });
  }
};

struct TestNetworkKey {
  static std::string newPath() {
    static uint64_t sequence = 0;
#ifdef _WIN32
    const auto process = GetCurrentProcessId();
#else
    const auto process = ::getpid();
#endif
    return (std::filesystem::temp_directory_path() /
      ("discrete-p2p-" + std::to_string(process) + "-" + std::to_string(++sequence) + "-" +
       std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".key")).string();
  }
  std::string path = newPath();
  TestNetworkKey() { createP2pTransportKey(path, P2pTransportContext::networkAlpn(network()), "node.transport.invalid"); }
  ~TestNetworkKey() { std::error_code ignored; std::filesystem::remove(path, ignored); }
  P2pTransportConfig config() const { auto c = required(); c.keyFile = path; c.name = "node.transport.invalid"; return c; }
};

class P2pTransportNative : public testing::Test {
protected:
  Dispatcher dispatcher;
  FixtureDeadline deadline{dispatcher};
  TcpListener listener{dispatcher, Ipv4Address("127.0.0.1"), 0};
  const uint16_t port = listener.getLocalPort();
  const std::string endpoint = "127.0.0.1:" + std::to_string(port);
  P2pTransport client{dispatcher, TcpConnector(dispatcher).connect(Ipv4Address("127.0.0.1"), port)};
  P2pTransport server{dispatcher, listener.accept()};
  P2pTransportContext clientProfile{required(), network()}, serverProfile{required(), network()};
  void handshake() {
    Context<> accept(dispatcher, [&] { server.startServer(serverProfile); });
    client.startClient(clientProfile, endpoint); accept.get();
    ASSERT_TRUE(client.ready()); ASSERT_TRUE(server.ready());
    ASSERT_TRUE(client.secure()); ASSERT_TRUE(server.secure()); ASSERT_FALSE(client.pinned());
  }
};

TEST(P2pTransportFixture, IndependentListenersUseDistinctPorts) {
  Dispatcher dispatcher;
  FixtureDeadline deadline(dispatcher);
  TcpListener first(dispatcher, Ipv4Address("127.0.0.1"), 0), second(dispatcher, Ipv4Address("127.0.0.1"), 0);
  ASSERT_NE(0, first.getLocalPort()); ASSERT_NE(first.getLocalPort(), second.getLocalPort());
  auto a = TcpConnector(dispatcher).connect(Ipv4Address("127.0.0.1"), first.getLocalPort());
  auto b = TcpConnector(dispatcher).connect(Ipv4Address("127.0.0.1"), second.getLocalPort());
  EXPECT_EQ(a.getSocket().local_endpoint().port(), first.accept().getPeerAddressAndPort().second);
  EXPECT_EQ(b.getSocket().local_endpoint().port(), second.accept().getPeerAddressAndPort().second);
}

TEST(P2pTransportFixture, BareAcceptHasABoundedFailure) {
  Dispatcher dispatcher;
  FixtureDeadline deadline(dispatcher, std::chrono::milliseconds(25));
  TcpListener listener(dispatcher, Ipv4Address("127.0.0.1"), 0);
  EXPECT_THROW(listener.accept(), InterruptedException);
}

TEST_F(P2pTransportNative, LevinDuplexAndMovePreserveSession) {
  EXPECT_THROW(client.write(reinterpret_cast<const uint8_t*>("x"), 1), std::runtime_error);
  handshake();
  P2pTransport moved(std::move(client));
  BinaryArray payload(1024 * 1024 + 7); std::iota(payload.begin(), payload.end(), uint8_t{0});
  Context<> receiver(dispatcher, [&] {
    LevinProtocol protocol(server); LevinProtocol::Command command;
    ASSERT_TRUE(protocol.readCommand(command)); EXPECT_EQ(812u, command.command); EXPECT_EQ(payload, command.buf);
    protocol.sendReply(812, payload, 1);
  });
  Context<> writer(dispatcher, [&] { LevinProtocol(moved).sendMessage(812, payload, true); });
  LevinProtocol::Command reply;
  EXPECT_TRUE(LevinProtocol(moved).readCommand(reply)); EXPECT_TRUE(reply.isResponse); EXPECT_EQ(payload, reply.buf);
  writer.get(); receiver.get(); EXPECT_THROW(moved.startLegacy(), std::runtime_error);
}

TEST_F(P2pTransportNative, NetworkMismatchNeverBecomesReady) {
  auto other = network(); ++other.data[0]; P2pTransportContext wrong(required(), other);
  Context<> accept(dispatcher, [&] { EXPECT_THROW(server.startServer(serverProfile), std::exception); });
  EXPECT_THROW(client.startClient(wrong, endpoint), std::exception); accept.get();
  EXPECT_FALSE(client.ready()); EXPECT_FALSE(server.ready()); EXPECT_THROW(client.startLegacy(), std::exception);
}

TEST_F(P2pTransportNative, RequiredListenerRejectsPlaintext) {
  client.startLegacy();
  Context<> accept(dispatcher, [&] { EXPECT_THROW(server.startServer(serverProfile), std::exception); });
  LevinProtocol(client).sendMessage(812, BinaryArray{1, 2, 3}, false); accept.get(); EXPECT_FALSE(server.ready());
}

TEST_F(P2pTransportNative, MixedListenerPreservesFirstLegacyByte) {
  auto config = required(); config.mode = P2pTransportMode::Mixed; P2pTransportContext mixed(config, network());
  Context<> accept(dispatcher, [&] {
    server.startServer(mixed); EXPECT_FALSE(server.secure()); LevinProtocol::Command command;
    EXPECT_TRUE(LevinProtocol(server).readCommand(command)); EXPECT_EQ(812u, command.command); EXPECT_EQ(BinaryArray({1, 2, 3}), command.buf);
  });
  client.startLegacy(); LevinProtocol(client).sendMessage(812, BinaryArray{1, 2, 3}, false); accept.get();
}

TEST_F(P2pTransportNative, CancelBeforePrefixCompletesAndDrains) {
  Context<> accept(dispatcher, [&] { EXPECT_THROW(server.startServer(serverProfile), InterruptedException); });
  dispatcher.yield(); accept.interrupt(); accept.get(); EXPECT_FALSE(server.ready());
}

TEST_F(P2pTransportNative, CancelClientHandshakeClosesAndDrains) {
  Context<> connect(dispatcher, [&] { EXPECT_THROW(client.startClient(clientProfile, endpoint), InterruptedException); });
  dispatcher.yield(); connect.interrupt(); connect.get(); EXPECT_FALSE(client.ready());
}

TEST_F(P2pTransportNative, CancelReadAlsoStopsConcurrentWrite) {
  handshake(); BinaryArray payload(32 * 1024 * 1024, 7);
  Context<> reader(dispatcher, [&] { uint8_t byte; EXPECT_THROW(client.read(&byte, 1), InterruptedException); });
  Context<> writer(dispatcher, [&] { EXPECT_THROW(LevinProtocol(client).sendMessage(812, payload, false), std::exception); });
  Timer(dispatcher).sleep(std::chrono::milliseconds(20)); reader.interrupt(); reader.get(); writer.get(); EXPECT_FALSE(client.ready());
}

TEST_F(P2pTransportNative, CloseMovedHandleDrainsAnOutstandingRead) {
  handshake();
  Context<> reader(dispatcher, [&] { uint8_t byte = 0; EXPECT_THROW(client.read(&byte, 1), std::exception); });
  dispatcher.yield();
  P2pTransport moved(std::move(client));
  moved.close(); reader.get(); EXPECT_FALSE(moved.ready());
}

TEST_F(P2pTransportNative, TruncatedTlsDoesNotCompleteLevinCommand) {
  handshake();
  Context<> receiver(dispatcher, [&] { LevinProtocol::Command command; EXPECT_THROW(LevinProtocol(client).readCommand(command), std::exception); });
  server.write(reinterpret_cast<const uint8_t*>("incomplete"), 10); server.close(); receiver.get();
}

TEST_F(P2pTransportNative, UnknownPinAndWrongServiceFailClosed) {
  auto config = required(); std::string ep;
  config.pins.emplace(endpoint, P2pTransportConfig::parsePin(endpoint + ",node.transport.invalid," + std::string(64, '0'), ep));
  P2pTransportContext pinned(config, network());
  Context<> accept(dispatcher, [&] { EXPECT_THROW(server.startServer(serverProfile), std::exception); });
  EXPECT_THROW(client.startClient(pinned, endpoint), std::exception); accept.get(); EXPECT_FALSE(client.ready());
}

TEST_F(P2pTransportNative, ExactPinAndNamedServerAuthenticate) {
  TestNetworkKey key;
  P2pTransportContext named(key.config(), network());
  auto config = required(); std::string ep;
  config.pins.emplace(endpoint, P2pTransportConfig::parsePin(endpoint + ",node.transport.invalid," + named.publicKeyFingerprint(), ep));
  P2pTransportContext pinned(config, network());
  Context<> accept(dispatcher, [&] { server.startServer(named); });
  client.startClient(pinned, endpoint); accept.get();
  EXPECT_TRUE(client.ready()); EXPECT_TRUE(client.pinned());
  EXPECT_TRUE(server.ready()); EXPECT_FALSE(server.pinned());
  const uint8_t sent = 7; client.write(&sent, 1); uint8_t received = 0;
  EXPECT_EQ(1u, server.read(&received, 1)); EXPECT_EQ(sent, received);
}

TEST_F(P2pTransportNative, MatchingNameWithWrongPinStillFails) {
  TestNetworkKey key; P2pTransportContext named(key.config(), network());
  auto config = required(); std::string ep;
  config.pins.emplace(endpoint, P2pTransportConfig::parsePin(endpoint + ",node.transport.invalid," + std::string(64, '0'), ep));
  P2pTransportContext pinned(config, network());
  Context<> accept(dispatcher, [&] { EXPECT_THROW(server.startServer(named), std::exception); });
  EXPECT_THROW(client.startClient(pinned, endpoint), std::exception); accept.get();
  EXPECT_FALSE(client.ready()); EXPECT_FALSE(server.ready());
}

TEST_F(P2pTransportNative, MaximumValidLevinMessageIsPreserved) {
  handshake();
  BinaryArray payload(100000000);
  for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<uint8_t>(i);
  Context<> receiver(dispatcher, [&] {
    LevinProtocol::Command command; EXPECT_TRUE(LevinProtocol(server).readCommand(command));
    EXPECT_EQ(payload, command.buf);
  });
  LevinProtocol(client).sendMessage(812, payload, false); receiver.get();
}

TEST_F(P2pTransportNative, SilentPrefixHasFiniteDeadline) {
  const auto start = std::chrono::steady_clock::now();
  EXPECT_THROW(server.startServer(serverProfile), std::exception);
  const auto elapsed = std::chrono::steady_clock::now() - start;
  EXPECT_LT(elapsed, std::chrono::seconds(7)); EXPECT_FALSE(server.ready());
}

#ifndef _WIN32
TEST(P2pTransportKeys, NonRegularFileFailsWithoutBlockingStartup) {
  TestNetworkKey key;
  std::filesystem::remove(key.path);
  ASSERT_EQ(0, ::mkfifo(key.path.c_str(), 0600));
  EXPECT_THROW(P2pTransportContext profile(key.config(), network()), std::exception);
}

TEST(P2pTransportKeys, BroadPermissionsAreRejected) {
  TestNetworkKey key;
  std::filesystem::permissions(key.path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write | std::filesystem::perms::group_read);
  EXPECT_THROW(P2pTransportContext profile(key.config(), network()), std::exception);
}
#else
TEST(P2pTransportKeys, BroadPermissionsAreRejected) {
  TestNetworkKey key;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  PACL original = nullptr, changed = nullptr;
  const auto path = std::filesystem::u8path(key.path);
  ASSERT_EQ(ERROR_SUCCESS, GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
    nullptr, nullptr, &original, nullptr, &descriptor));
  alignas(DWORD) std::array<unsigned char, SECURITY_MAX_SID_SIZE> everyone{};
  DWORD size = static_cast<DWORD>(everyone.size());
  ASSERT_TRUE(CreateWellKnownSid(WinWorldSid, nullptr, everyone.data(), &size));
  EXPLICIT_ACCESSW entry{};
  entry.grfAccessPermissions = GENERIC_READ;
  entry.grfAccessMode = GRANT_ACCESS;
  entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  entry.Trustee.ptstrName = reinterpret_cast<LPWSTR>(everyone.data());
  const auto aclStatus = SetEntriesInAclW(1, &entry, original, &changed);
  LocalFree(descriptor);
  ASSERT_EQ(ERROR_SUCCESS, aclStatus);
  const auto status = SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, changed, nullptr);
  LocalFree(changed);
  ASSERT_EQ(ERROR_SUCCESS, status);
  EXPECT_THROW(P2pTransportContext profile(key.config(), network()), std::exception);
}
#endif

TEST(P2pTransportProfiles, RejectsNegotiationOutsideThePinnedProfile) {
  for (const auto* variant : {"classical-group", "classical-signature", "aes128", "no-alpn", "x509-only"}) {
    SCOPED_TRACE(variant);
    Dispatcher dispatcher;
    FixtureDeadline deadline(dispatcher);
    TcpListener listener(dispatcher, Ipv4Address("127.0.0.1"), 0);
    const auto port = listener.getLocalPort();
    P2pTransportContext profile(required(), network());
    std::exception_ptr clientFailure;
    std::thread client([&] {
      try {
        boost::asio::io_context io;
        boost::asio::ssl::context context(boost::asio::ssl::context::tls_client);
        SSL_CTX* ctx = context.native_handle();
        SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
        SSL_CTX_set1_groups_list(ctx, std::string(variant) == "classical-group" ? "X25519" : "X25519MLKEM768");
        SSL_CTX_set1_sigalgs_list(ctx, std::string(variant) == "classical-signature" ? "ed25519" : "mldsa65");
        SSL_CTX_set_ciphersuites(ctx, std::string(variant) == "aes128" ? "TLS_AES_128_GCM_SHA256" : "TLS_AES_256_GCM_SHA384");
        if (std::string(variant) != "x509-only") { const unsigned char rpk = TLSEXT_cert_type_rpk; SSL_CTX_set1_server_cert_type(ctx, &rpk, 1); }
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(io, context);
        if (std::string(variant) != "no-alpn") {
          const auto alpn = profile.alpn(); const auto wire = std::string(1, static_cast<char>(alpn.size())) + alpn;
          SSL_set_alpn_protos(stream.native_handle(), reinterpret_cast<const unsigned char*>(wire.data()), static_cast<unsigned>(wire.size()));
        }
        // This test peer deliberately offers an incompatible profile. No trust
        // override from this fixture is used by the production transport.
        stream.next_layer().connect({boost::asio::ip::make_address("127.0.0.1"), port});
        boost::system::error_code ignored; stream.handshake(boost::asio::ssl::stream_base::client, ignored);
        stream.next_layer().close(ignored);
      } catch (...) { clientFailure = std::current_exception(); }
    });
    P2pTransport server(dispatcher, listener.accept());
    EXPECT_THROW(server.startServer(profile), std::exception); EXPECT_FALSE(server.ready());
    client.join(); if (clientFailure) std::rethrow_exception(clientFailure);
  }
}

TEST(P2pTransportNativeLink, IncrementalTcpDeliveryWithDelayPreservesMessages) {
  Dispatcher dispatcher;
  FixtureDeadline deadline(dispatcher);
  TcpListener frontListener(dispatcher, Ipv4Address("127.0.0.1"), 0), backListener(dispatcher, Ipv4Address("127.0.0.1"), 0);
  P2pTransport client(dispatcher, TcpConnector(dispatcher).connect(Ipv4Address("127.0.0.1"), frontListener.getLocalPort()));
  auto front = frontListener.accept();
  auto back = TcpConnector(dispatcher).connect(Ipv4Address("127.0.0.1"), backListener.getLocalPort());
  P2pTransport server(dispatcher, backListener.accept());
  // The proxy models explicit 113-byte fragments and timer delays. Avoid adding
  // a second, platform-dependent Nagle/delayed-ACK delay to each fragment.
  front.getSocket().set_option(boost::asio::ip::tcp::no_delay(true));
  back.getSocket().set_option(boost::asio::ip::tcp::no_delay(true));
  auto pump = [&](TcpConnection& from, TcpConnection& to) {
    try {
      std::array<uint8_t, 113> bytes{};
      for (;;) {
        const auto n = from.read(bytes.data(), bytes.size()); if (!n) break;
        Timer(dispatcher).sleep(std::chrono::milliseconds(1));
        for (size_t sent = 0; sent < n;) { const auto written = to.write(bytes.data() + sent, n - sent); if (!written) return; sent += written; }
      }
    } catch (const std::exception&) {} // Teardown closes both proxy sockets.
  };
  Context<> forward(dispatcher, [&] { pump(front, back); }), reverse(dispatcher, [&] { pump(back, front); });
  P2pTransportContext profile(required(), network());
  Context<> accept(dispatcher, [&] { server.startServer(profile); });
  client.startClient(profile, "127.0.0.1:" + std::to_string(frontListener.getLocalPort())); accept.get();
  BinaryArray payload(8193); std::iota(payload.begin(), payload.end(), uint8_t{0});
  Context<> receive(dispatcher, [&] {
    LevinProtocol::Command command; EXPECT_TRUE(LevinProtocol(server).readCommand(command)); EXPECT_EQ(payload, command.buf);
    LevinProtocol(server).sendReply(812, payload, 1);
  });
  LevinProtocol(client).sendMessage(812, payload, true);
  LevinProtocol::Command response; EXPECT_TRUE(LevinProtocol(client).readCommand(response)); EXPECT_EQ(payload, response.buf); receive.get();
  client.close(); server.close(); forward.interrupt(); reverse.interrupt(); forward.get(); reverse.get();
}

TEST_F(P2pTransportNative, SixteenHandshakesPreserveEstablishedProgress) {
  handshake();
  const auto warmRss = residentBytes();
  size_t peakRss = warmRss;
  std::vector<std::unique_ptr<P2pTransport>> clients, servers;
  std::vector<std::unique_ptr<Context<>>> jobs;
  for (uint32_t i = 0; i < 16; ++i) {
    ASSERT_TRUE(serverProfile.admit(i, true));
    clients.emplace_back(new P2pTransport(dispatcher, TcpConnector(dispatcher).connect(Ipv4Address("127.0.0.1"), port)));
    servers.emplace_back(new P2pTransport(dispatcher, listener.accept()));
  }
  EXPECT_FALSE(serverProfile.admit(16, true)); EXPECT_TRUE(serverProfile.admit(16, false));
  double maxTimerDelayMs = 0, maxAfterHandshakeMs = 0;
  bool handshakesDone = false;
  const auto burstStart = std::chrono::steady_clock::now();
  const auto burstCpu = P2pTransportTest::processCpuSeconds();
  unsigned exchanges = 0;
  Context<> echo(dispatcher, [&] {
    for (int i = 0; i < 16; ++i) { uint8_t value = 0; EXPECT_EQ(1u, server.read(&value, 1)); server.write(&value, 1); }
  });
  Context<> progress(dispatcher, [&] {
    for (int i = 0; i < 16; ++i) {
      const auto start = std::chrono::steady_clock::now(); Timer(dispatcher).sleep(std::chrono::milliseconds(1));
      peakRss = std::max(peakRss, residentBytes());
      maxTimerDelayMs = std::max(maxTimerDelayMs, std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count() - 1);
      if (handshakesDone) maxAfterHandshakeMs = std::max(maxAfterHandshakeMs, std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count() - 1);
      const uint8_t sent = static_cast<uint8_t>(i); client.write(&sent, 1); uint8_t received = 0;
      EXPECT_EQ(1u, client.read(&received, 1)); EXPECT_EQ(sent, received); ++exchanges;
    }
  });
  for (size_t i = 0; i < clients.size(); ++i) {
    jobs.emplace_back(new Context<>(dispatcher, [&, i] { servers[i]->startServer(serverProfile); }));
    jobs.emplace_back(new Context<>(dispatcher, [&, i] { clients[i]->startClient(clientProfile, endpoint); }));
  }
  for (auto& job : jobs) job->get();
  handshakesDone = true;
  const auto burstMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - burstStart).count();
  const auto burstCpuMs = 1000.0 * (P2pTransportTest::processCpuSeconds() - burstCpu);
  progress.get(); echo.get();
  std::cout << "{\"burst_ms\":" << burstMs << ",\"burst_cpu_ms\":" << burstCpuMs << ",\"max_timer_after_handshakes_ms\":" << maxAfterHandshakeMs << "}\n";
  EXPECT_EQ(16u, exchanges); EXPECT_LT(maxTimerDelayMs, 50.0);
  const auto establishedRss = residentBytes();
  // Both endpoints live in this process: 16 additional pairs = 32 TLS endpoints.
  EXPECT_LE(establishedRss, warmRss + 32 * 1024 * 1024);
  EXPECT_LE(peakRss, warmRss + 64 * 1024 * 1024);
  std::cout << "{\"rss_warm\":" << warmRss << ",\"rss_established\":" << establishedRss << ",\"rss_sampled_peak\":" << peakRss << ",\"additional_tls_endpoints\":32}\n";
  std::cout << "{\"handshake_pairs\":16,\"established_exchanges\":" << exchanges << ",\"max_timer_delay_ms\":" << maxTimerDelayMs << "}\n";
  for (uint32_t i = 0; i < 16; ++i) serverProfile.release(i, true);
  serverProfile.release(16, false);
}
TEST(P2pTransportKeys, PersistentIdentityBoundToNetworkAndService) {
  const auto path = TestNetworkKey::newPath();
  ASSERT_FALSE(std::filesystem::exists(path));
  createP2pTransportKey(path, P2pTransportContext::networkAlpn(network()), "node.transport.invalid");
  struct Cleanup { std::string path; ~Cleanup() { std::filesystem::remove(path); } } cleanup{path};
  auto config = required(); config.keyFile = path; config.name = "node.transport.invalid";
  P2pTransportContext first(config, network()), second(config, network());
  EXPECT_EQ(first.publicKeyFingerprint(), second.publicKeyFingerprint());
  EXPECT_THROW(createP2pTransportKey(path, first.alpn(), config.name), std::exception);
  auto other = network(); ++other.data[0]; EXPECT_THROW(P2pTransportContext wrong(config, other), std::exception);
  config.name = "other.transport.invalid"; EXPECT_THROW(P2pTransportContext wrong(config, network()), std::exception);
}
#else
TEST(P2pTransportPolicy, UnsupportedEnabledModeFailsAtStartup) {
  EXPECT_THROW(P2pTransportContext context(required(), network()), std::runtime_error);
}
#endif
