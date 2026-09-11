#include "P2pTransport.h"
#include <System/InterruptedException.h>
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <utility>

#if defined(DISCRETE_PQ_P2P)
#include "P2pTransportKey.h"
#include <boost/asio/ssl.hpp>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#endif

namespace CryptoNote {
namespace {
void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}
}

struct P2pTransportContext::Impl {
  P2pTransportConfig config;
  std::string alpn;
  size_t incoming = 0, outgoing = 0;
  std::map<uint32_t, size_t> incomingByIp, outgoingByIp;
#if defined(DISCRETE_PQ_P2P)
  std::unique_ptr<boost::asio::ssl::context> client, server;
  std::array<uint8_t, 32> fingerprint{};
#endif
  Impl(P2pTransportConfig value, const boost::uuids::uuid& network)
    : config(std::move(value)), alpn(P2pTransportContext::networkAlpn(network)) {}
};

#if defined(DISCRETE_PQ_P2P)
namespace {
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Cert = std::unique_ptr<X509, decltype(&X509_free)>;

std::array<uint8_t, 32> fingerprint(EVP_PKEY* key) {
  require(key != nullptr && EVP_PKEY_is_a(key, "ML-DSA-65") == 1, "P2P requires an ML-DSA-65 identity");
  const int size = i2d_PUBKEY(key, nullptr);
  require(size > 0 && size < 8192, "Invalid P2P public key encoding");
  std::vector<uint8_t> der(static_cast<size_t>(size));
  auto* cursor = der.data();
  require(i2d_PUBKEY(key, &cursor) == size, "Cannot encode P2P public key");
  std::array<uint8_t, 32> result{};
  unsigned int length = 0;
  require(EVP_Digest(der.data(), der.size(), result.data(), &length, EVP_sha256(), nullptr) == 1 && length == result.size(), "Cannot hash P2P public key");
  return result;
}

void configureTls(SSL_CTX* ctx) {
  require(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1 &&
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 1, "TLS 1.3 is required");
  require(SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768") == 1, "X25519MLKEM768 is required");
  require(SSL_CTX_set1_sigalgs_list(ctx, "mldsa65") == 1, "TLS ML-DSA-65 is required");
  require(SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256") == 1, "P2P cipher suite unavailable");
  const unsigned char raw = TLSEXT_cert_type_rpk;
  require(SSL_CTX_set1_server_cert_type(ctx, &raw, 1) == 1, "TLS raw public keys are required");
  SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION);
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
  require(SSL_CTX_set_num_tickets(ctx, 0) == 1 && SSL_CTX_set_max_early_data(ctx, 0) == 1, "Cannot disable TLS resumption");
  SSL_CTX_set_max_cert_list(ctx, 16384);
  SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
}

// This wrapper bounds ciphertext staging and pre-ready I/O. TLS syntax and
// authenticated record processing remain exclusively OpenSSL's responsibility.
struct WireState {
  boost::asio::ip::tcp::socket* socket;
  bool ready = false;
  bool closed = false;
  size_t handshakeRead = 0, handshakeWritten = 0;
  static constexpr size_t MAX_HANDSHAKE_BYTES = 65536;
  void close() noexcept {
    closed = true;
    boost::system::error_code ignored;
    socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
    socket->close(ignored);
  }
};

class BoundedSocket {
public:
  using executor_type = boost::asio::ip::tcp::socket::executor_type;
  using lowest_layer_type = boost::asio::ip::tcp::socket;
  explicit BoundedSocket(std::shared_ptr<WireState> value) : state(std::move(value)) {}
  executor_type get_executor() noexcept { return state->socket->get_executor(); }
  lowest_layer_type& lowest_layer() { return *state->socket; }
  const lowest_layer_type& lowest_layer() const { return *state->socket; }
  template<class Buffers, class Handler>
  void async_read_some(const Buffers& buffers, Handler&& handler) {
    if (!state->ready && state->handshakeRead >= WireState::MAX_HANDSHAKE_BYTES) {
      state->close();
      boost::asio::post(get_executor(), [h = std::forward<Handler>(handler)]() mutable { h(boost::asio::error::message_size, 0); });
      return;
    }
    const auto limit = state->ready ? size_t{16384} : std::min(size_t{16384}, WireState::MAX_HANDSHAKE_BYTES - state->handshakeRead);
    state->socket->async_read_some(boost::asio::buffer(buffers, limit),
      [s = state, h = std::forward<Handler>(handler)](boost::system::error_code ec, size_t n) mutable {
        if (!s->ready && (s->handshakeRead += n) > WireState::MAX_HANDSHAKE_BYTES) {
          s->close(); ec = boost::asio::error::message_size; n = 0;
        }
        h(ec, n);
      });
  }
  template<class Buffers, class Handler>
  void async_write_some(const Buffers& buffers, Handler&& handler) {
    // Include TLS header/tag overhead; do not split off a tiny record tail.
    if (!state->ready && state->handshakeWritten >= WireState::MAX_HANDSHAKE_BYTES) {
      state->close();
      boost::asio::post(get_executor(), [h = std::forward<Handler>(handler)]() mutable { h(boost::asio::error::message_size, 0); });
      return;
    }
    const auto limit = state->ready ? size_t{17408} : std::min(size_t{17408}, WireState::MAX_HANDSHAKE_BYTES - state->handshakeWritten);
    state->socket->async_write_some(boost::asio::buffer(buffers, limit),
      [s = state, h = std::forward<Handler>(handler)](boost::system::error_code ec, size_t n) mutable {
        if (!s->ready && (s->handshakeWritten += n) > WireState::MAX_HANDSHAKE_BYTES) {
          s->close(); ec = boost::asio::error::message_size; n = 0;
        }
        h(ec, n);
      });
  }
private:
  std::shared_ptr<WireState> state;
};
}
#endif

struct P2pTransport::Impl : std::enable_shared_from_this<P2pTransport::Impl> {
  System::Dispatcher& dispatcher;
  System::TcpConnection connection;
  bool started = false, isReady = false, isSecure = false, isPinned = false, closed = false;
  bool reading = false, writing = false;
  bool hasPrefix = false;
  uint8_t prefix = 0;
  std::shared_ptr<P2pTransportContext::Impl> context;
#if defined(DISCRETE_PQ_P2P)
  std::shared_ptr<WireState> wire;
  std::unique_ptr<boost::asio::ssl::stream<BoundedSocket>> tls;
  P2pTransportPin expected;
  uint64_t sentBytes = 0, sentRecords = 0, receivedRecords = 0;
  uint64_t sentKeyUpdates = 0, receivedKeyUpdates = 0;
  size_t controlCredits = 32;
  uint64_t receivedSinceControlCredit = 0;
  std::chrono::steady_clock::time_point controlWindow = std::chrono::steady_clock::now();

  static int dataIndex() {
    static const int index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    require(index >= 0, "Cannot allocate P2P TLS policy index");
    return index;
  }

  static int verify(int ok, X509_STORE_CTX* store) noexcept {
    // A dedicated P2P verifier. It never accepts another X.509 error and never
    // changes the HTTPS trust store or its verification callback.
    try {
      auto* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx()));
      auto* self = static_cast<Impl*>(SSL_get_ex_data(ssl, dataIndex()));
      if (!self) return 0;
      EVP_PKEY* key = X509_STORE_CTX_get0_rpk(store);
      if (!key || EVP_PKEY_is_a(key, "ML-DSA-65") != 1) return 0;
      if (!ok && X509_STORE_CTX_get_error(store) != X509_V_ERR_RPK_UNTRUSTED) return 0;
      if (!self->isPinned) return 1;
      const auto actual = fingerprint(key);
      if (CRYPTO_memcmp(actual.data(), self->expected.sha256.data(), actual.size()) != 0) return 0;
      X509_STORE_CTX_set_error(store, X509_V_OK);
      return 1;
    } catch (...) { return 0; }
  }

  static void message(int writing, int, int type, const void* data, size_t size, SSL*, void* arg) noexcept {
    auto* self = static_cast<Impl*>(arg);
    if (!self->isReady || self->closed) return;
    if (type == SSL3_RT_HEADER) {
      auto& count = writing ? self->sentRecords : self->receivedRecords;
      // Close before reaching the conservative per-direction hard limit.
      if (++count >= (uint64_t{1} << 22)) self->close();
    }
    if (type != SSL3_RT_HANDSHAKE || size == 0) return;
    const auto kind = *static_cast<const uint8_t*>(data);
    if (!writing) {
      const auto now = std::chrono::steady_clock::now();
      if (now - self->controlWindow >= std::chrono::minutes(1)) { self->controlCredits = 32; self->controlWindow = now; }
      if (!self->controlCredits || kind != SSL3_MT_KEY_UPDATE) { self->close(); return; }
      --self->controlCredits;
    }
    if (kind == SSL3_MT_KEY_UPDATE) {
      if (writing) { self->sentBytes = 0; self->sentRecords = 0; ++self->sentKeyUpdates; }
      else { self->receivedRecords = 0; ++self->receivedKeyUpdates; }
    }
  }

  void makeTls(bool server) {
    // Finished and the first Levin message are separate TLS records. Nagle plus
    // delayed ACK otherwise stalls that dependency (and reverse ping) by an RTT.
    connection.getSocket().set_option(boost::asio::ip::tcp::no_delay(true));
    wire = std::make_shared<WireState>();
    wire->socket = &connection.getSocket();
    wire->handshakeRead = server ? 1 : 0; // The listener already consumed its prefix.
    tls.reset(new boost::asio::ssl::stream<BoundedSocket>(BoundedSocket(wire), server ? *context->server : *context->client));
    SSL* ssl = tls->native_handle();
    require(SSL_set_ex_data(ssl, dataIndex(), this) == 1, "Cannot attach P2P verification policy");
    SSL_set_msg_callback(ssl, message);
    SSL_set_msg_callback_arg(ssl, this);
    if (!server) SSL_set_verify(ssl, SSL_VERIFY_PEER, verify);
  }

  void checkProfile(bool server) {
    SSL* ssl = tls->native_handle();
    require(!closed && SSL_is_init_finished(ssl) == 1 && SSL_version(ssl) == TLS1_3_VERSION && SSL_session_reused(ssl) == 0, "Incomplete P2P TLS profile");
    const char* group = SSL_group_to_name(ssl, SSL_get_negotiated_group(ssl));
    require(group && std::strcmp(group, "X25519MLKEM768") == 0, "P2P hybrid group mismatch");
    const char* cipher = SSL_get_cipher_name(ssl);
    require(cipher && (std::strcmp(cipher, "TLS_AES_256_GCM_SHA384") == 0 || std::strcmp(cipher, "TLS_CHACHA20_POLY1305_SHA256") == 0), "P2P cipher mismatch");
    require(SSL_get_negotiated_server_cert_type(ssl) == TLSEXT_cert_type_rpk, "P2P requires a raw public key");
    const unsigned char* negotiated = nullptr;
    unsigned int length = 0;
    SSL_get0_alpn_selected(ssl, &negotiated, &length);
    require(length == context->alpn.size() && negotiated && std::memcmp(negotiated, context->alpn.data(), length) == 0, "P2P network ALPN mismatch");
    if (!server) {
      EVP_PKEY* key = SSL_get0_peer_rpk(ssl);
      const auto actual = fingerprint(key);
      int signature = NID_undef;
      require(SSL_get_peer_signature_type_nid(ssl, &signature) == 1 && signature == NID_ML_DSA_65, "P2P signature mismatch");
      const long result = SSL_get_verify_result(ssl);
      require(result == X509_V_OK || (!isPinned && result == X509_V_ERR_RPK_UNTRUSTED), "P2P peer verification failed");
      if (isPinned) {
        const char* name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        require(name && expected.name == name && CRYPTO_memcmp(actual.data(), expected.sha256.data(), actual.size()) == 0, "P2P service pin mismatch");
      }
    }
    isSecure = true;
    isReady = true;
    wire->ready = true;
  }
#endif

  Impl(System::Dispatcher& d, System::TcpConnection&& c) : dispatcher(d), connection(std::move(c)) {}
  ~Impl() { close(); }
  void close() noexcept {
    closed = true;
    isReady = false;
    try {
      boost::system::error_code ignored;
      connection.getSocket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
      connection.getSocket().close(ignored);
    } catch (...) {}
  }

  // Asio serializes its SSL engine and concurrent read/write I/O internally.
  // Wait for the cancellation completion before releasing caller buffers.
  template<class Start>
  size_t wait(Start start) {
    if (dispatcher.interrupted()) { close(); throw System::InterruptedException(); }
    require(!closed, "P2P connection is closed");
    bool done = false, cancelled = false;
    size_t transferred = 0;
    boost::system::error_code error;
    auto* current = dispatcher.getCurrentContext();
    const auto owner = shared_from_this();
    current->interruptProcedure = [owner, &cancelled] { cancelled = true; owner->close(); };
    try {
      start([&, owner, current](const boost::system::error_code& ec, size_t bytes) {
        error = ec; transferred = bytes; done = true; owner->dispatcher.pushContext(current);
      });
    } catch (...) { current->interruptProcedure = nullptr; close(); throw; }
    while (!done) {
      if (dispatcher.interrupted()) { cancelled = true; close(); }
      dispatcher.dispatch();
    }
    current->interruptProcedure = nullptr;
    if (cancelled || dispatcher.interrupted()) {
      close(); throw System::InterruptedException();
    }
    if (error) {
      close();
      // TLS EOF without close_notify is stream_truncated, never a clean EOF.
      if (error == boost::asio::error::eof) return 0;
      throw std::runtime_error("P2P stream: " + error.message());
    }
    require(!closed, "P2P connection closed during I/O");
    return transferred;
  }

  struct Deadline {
    boost::asio::steady_timer timer;
    explicit Deadline(const std::shared_ptr<Impl>& owner)
      : timer(owner->dispatcher.getIoContext(), std::chrono::milliseconds(P2pTransportContext::HANDSHAKE_TIMEOUT_MS)) {
      timer.async_wait([owner](const boost::system::error_code& ec) { if (!ec) owner->close(); });
    }
    ~Deadline() = default; // The timer destructor cancels outstanding waits.
  };
};

bool P2pTransportContext::supported() {
#if defined(DISCRETE_PQ_P2P)
  return true;
#else
  return false;
#endif
}

P2pTransportContext::P2pTransportContext(P2pTransportConfig config, const boost::uuids::uuid& network)
  : impl(std::make_shared<Impl>(std::move(config), network)) {
  impl->config.validate();
  if (impl->config.mode == P2pTransportMode::Off) return;
  require(supported(), "PQ P2P requires a build with OpenSSL 3.5 or newer");
#if defined(DISCRETE_PQ_P2P)
  impl->client.reset(new boost::asio::ssl::context(boost::asio::ssl::context::tls));
  impl->server.reset(new boost::asio::ssl::context(boost::asio::ssl::context::tls));
  configureTls(impl->client->native_handle());
  configureTls(impl->server->native_handle());
  Key key(nullptr, EVP_PKEY_free);
  if (impl->config.keyFile.empty()) key.reset(EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-DSA-65"));
  else key.reset(loadP2pTransportKey(impl->config.keyFile, impl->alpn, impl->config.name));
  impl->fingerprint = fingerprint(key.get());
  // OpenSSL's certificate API supplies the local key; only its SPKI is sent.
  Cert carrier(X509_new(), X509_free);
  require(carrier != nullptr && X509_set_version(carrier.get(), 2) == 1, "Cannot create P2P key carrier");
  require(ASN1_INTEGER_set(X509_get_serialNumber(carrier.get()), 1) == 1, "P2P key serial");
  require(X509_gmtime_adj(X509_getm_notBefore(carrier.get()), -60) != nullptr && X509_gmtime_adj(X509_getm_notAfter(carrier.get()), 315360000L) != nullptr, "P2P key carrier validity");
  require(X509_set_pubkey(carrier.get(), key.get()) == 1 && X509_sign(carrier.get(), key.get(), nullptr) > 0, "P2P key carrier signature");
  SSL_CTX* server = impl->server->native_handle();
  require(SSL_CTX_use_certificate(server, carrier.get()) == 1 && SSL_CTX_use_PrivateKey(server, key.get()) == 1 && SSL_CTX_check_private_key(server) == 1, "Cannot configure P2P server identity");
  SSL_CTX_set_alpn_select_cb(server, [](SSL*, const unsigned char** out, unsigned char* length, const unsigned char* in, unsigned int size, void* arg) {
    auto* self = static_cast<Impl*>(arg);
    if (size != self->alpn.size() + 1 || in[0] != self->alpn.size() || std::memcmp(in + 1, self->alpn.data(), self->alpn.size()) != 0) return SSL_TLSEXT_ERR_ALERT_FATAL;
    *out = in + 1; *length = in[0]; return SSL_TLSEXT_ERR_OK;
  }, impl.get());
  SSL_CTX_set_tlsext_servername_arg(server, impl.get());
  const auto serviceNameCallback = +[](SSL* ssl, int* alert, void* arg) {
    auto* self = static_cast<Impl*>(arg);
    const char* name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (name && (self->config.name.empty() || self->config.name != name)) {
      *alert = SSL_AD_UNRECOGNIZED_NAME; return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    return SSL_TLSEXT_ERR_OK;
  };
  SSL_CTX_set_tlsext_servername_callback(server, serviceNameCallback);
#endif
}

P2pTransportContext::~P2pTransportContext() = default;
const P2pTransportConfig& P2pTransportContext::config() const { return impl->config; }
const std::string& P2pTransportContext::alpn() const { return impl->alpn; }
std::string P2pTransportContext::publicKeyFingerprint() const {
  if (impl->config.mode == P2pTransportMode::Off) return {};
  std::string result;
#if defined(DISCRETE_PQ_P2P)
  static const char hex[] = "0123456789abcdef";
  for (const auto byte : impl->fingerprint) { result += hex[byte >> 4]; result += hex[byte & 15]; }
#endif
  return result;
}

bool P2pTransportContext::admit(uint32_t ip, bool incoming) {
  auto& count = incoming ? impl->incoming : impl->outgoing;
  auto& byIp = incoming ? impl->incomingByIp : impl->outgoingByIp;
  const auto limit = incoming ? MAX_INCOMING_HANDSHAKES : MAX_OUTGOING_HANDSHAKES;
  const auto found = byIp.find(ip);
  if (count >= limit || (found != byIp.end() && found->second >= MAX_HANDSHAKES_PER_IP)) return false;
  ++count; ++byIp[ip]; return true;
}
void P2pTransportContext::release(uint32_t ip, bool incoming) {
  auto& count = incoming ? impl->incoming : impl->outgoing;
  auto& byIp = incoming ? impl->incomingByIp : impl->outgoingByIp;
  const auto found = byIp.find(ip);
  if (found != byIp.end()) { if (--found->second == 0) byIp.erase(found); --count; }
}

P2pTransport::P2pTransport(System::Dispatcher& d, System::TcpConnection&& c) : impl(std::make_shared<Impl>(d, std::move(c))) {}
P2pTransport::P2pTransport(P2pTransport&&) noexcept = default;
P2pTransport& P2pTransport::operator=(P2pTransport&& other) noexcept {
  if (this != &other) { close(); impl = std::move(other.impl); }
  return *this;
}
P2pTransport::~P2pTransport() { close(); }
void P2pTransport::close() noexcept { if (impl) impl->close(); }
bool P2pTransport::secure() const { return impl && impl->isSecure; }
bool P2pTransport::pinned() const { return impl && impl->isPinned; }
bool P2pTransport::ready() const { return impl && impl->isReady && !impl->closed; }
P2pTransport::Diagnostics P2pTransport::diagnostics() const {
  Diagnostics result;
#if defined(DISCRETE_PQ_P2P)
  if (impl && impl->isSecure) {
    result.cipher = SSL_get_cipher_name(impl->tls->native_handle());
    result.handshakeReceived = impl->wire->handshakeRead;
    result.handshakeSent = impl->wire->handshakeWritten;
    result.sentKeyUpdates = impl->sentKeyUpdates;
    result.receivedKeyUpdates = impl->receivedKeyUpdates;
  }
#endif
  return result;
}
std::pair<System::Ipv4Address, uint16_t> P2pTransport::getPeerAddressAndPort() const { return impl->connection.getPeerAddressAndPort(); }

void P2pTransport::startLegacy() {
  require(impl && !impl->started && !impl->closed, "P2P transport already selected");
  impl->started = impl->isReady = true;
}

void P2pTransport::startClient(P2pTransportContext& context, const std::string& endpoint) {
  const auto owner = impl;
  require(owner && !owner->started && !owner->closed, "P2P transport already selected");
  owner->started = true;
  owner->context = context.impl;
  require(context.config().mode != P2pTransportMode::Off && P2pTransportContext::supported(), "PQ P2P is disabled");
#if defined(DISCRETE_PQ_P2P)
  try {
    Impl::Deadline deadline(owner);
    const auto pin = context.config().pins.find(endpoint);
    owner->isPinned = pin != context.config().pins.end();
    if (owner->isPinned) owner->expected = pin->second;
    owner->makeTls(false);
    SSL* ssl = owner->tls->native_handle();
    if (owner->isPinned) require(SSL_set_tlsext_host_name(ssl, owner->expected.name.c_str()) == 1, "Cannot bind P2P service name");
    const std::string protocols = std::string(1, static_cast<char>(context.alpn().size())) + context.alpn();
    require(SSL_set_alpn_protos(ssl, reinterpret_cast<const unsigned char*>(protocols.data()), static_cast<unsigned int>(protocols.size())) == 0, "Cannot configure P2P network ALPN");
    owner->wait([&](auto completion) { owner->tls->async_handshake(boost::asio::ssl::stream_base::client,
      [completion](const boost::system::error_code& ec) { completion(ec, 0); }); });
    owner->checkProfile(false);
  } catch (...) { owner->close(); throw; }
#else
  (void)endpoint;
#endif
}

void P2pTransport::startServer(P2pTransportContext& context) {
  if (context.config().mode == P2pTransportMode::Off) { startLegacy(); return; }
  const auto owner = impl;
  require(owner && !owner->started && !owner->closed, "P2P transport already selected");
  owner->started = true;
  owner->context = context.impl;
  require(P2pTransportContext::supported(), "PQ P2P is unavailable in this build");
#if defined(DISCRETE_PQ_P2P)
  try {
    Impl::Deadline deadline(owner);
    const auto n = owner->wait([&](auto completion) {
      owner->connection.getSocket().async_read_some(boost::asio::buffer(&owner->prefix, 1), completion);
    });
    require(n == 1, "P2P transport prefix missing");
    if (owner->prefix == 0x01 && context.config().mode == P2pTransportMode::Mixed) {
      owner->hasPrefix = owner->isReady = true;
      return;
    }
    require(owner->prefix == 0x16, "P2P listener requires TLS");
    owner->makeTls(true);
    owner->wait([&](auto completion) {
      owner->tls->async_handshake(boost::asio::ssl::stream_base::server, boost::asio::buffer(&owner->prefix, 1), completion);
    });
    owner->checkProfile(true);
  } catch (...) { owner->close(); throw; }
#endif
}

size_t P2pTransport::read(uint8_t* data, size_t size) {
  const auto owner = impl;
  require(ready(), "P2P transport is not ready");
  require(!owner->reading, "Overlapping P2P reads");
  if (!size) return 0;
  if (owner->hasPrefix) { data[0] = owner->prefix; owner->hasPrefix = false; return 1; }
  if (!owner->isSecure) return owner->connection.read(data, size);
#if defined(DISCRETE_PQ_P2P)
  owner->reading = true;
  try {
    const auto n = owner->wait([&](auto completion) { owner->tls->async_read_some(boost::asio::buffer(data, size), completion); });
    // Permit legitimate updates on fast, long-lived transfers without allowing
    // unbounded controls on an idle connection. Only authenticated application
    // bytes earn credit; ciphertext padding and handshake bytes do not.
    owner->receivedSinceControlCredit += n;
    while (owner->receivedSinceControlCredit >= (uint64_t{1} << 28)) {
      owner->receivedSinceControlCredit -= uint64_t{1} << 28;
      owner->controlCredits = std::min(size_t{32}, owner->controlCredits + 1);
    }
    owner->reading = false;
    return n;
  } catch (...) { owner->reading = false; throw; }
#else
  return 0;
#endif
}

size_t P2pTransport::write(const uint8_t* data, size_t size) {
  const auto owner = impl;
  require(ready(), "P2P transport is not ready");
  require(!owner->writing, "Overlapping P2P writes");
  if (!size) return 0;
  if (!owner->isSecure) return owner->connection.write(data, size);
#if defined(DISCRETE_PQ_P2P)
  owner->writing = true;
  try {
    // One application record per call, bounded independently of Levin size.
    // Updates execute on the same dispatcher as every Asio SSL engine call.
    if (owner->sentBytes >= (uint64_t{1} << 30) || owner->sentRecords >= (uint64_t{1} << 20))
      require(SSL_key_update(owner->tls->native_handle(), SSL_KEY_UPDATE_NOT_REQUESTED) == 1, "P2P traffic key update failed");
    const auto n = owner->wait([&](auto completion) {
      owner->tls->async_write_some(boost::asio::buffer(data, std::min(size, size_t{16384})), completion);
    });
    require(n != 0, "P2P TLS write made no progress");
    owner->sentBytes += n;
    owner->writing = false;
    return n;
  } catch (...) { owner->writing = false; owner->close(); throw; }
#else
  return 0;
#endif
}
}
