#include <P2p/P2pTransport.h>
#include <P2p/P2pTransportKey.h>
#include <P2p/P2pNetworks.h>
#include <iostream>
#include <stdexcept>

int main(int argc, char** argv) {
  try {
    if (argc != 4 || (std::string(argv[1]) != "mainnet" && std::string(argv[1]) != "testnet")) {
      std::cerr << "Usage: p2p_transport_keygen mainnet|testnet service-name new-key-file\n";
      return 2;
    }
    auto network = CryptoNote::CRYPTONOTE_NETWORK;
    if (std::string(argv[1]) == "testnet") ++network.data[0];
    CryptoNote::createP2pTransportKey(argv[3], CryptoNote::P2pTransportContext::networkAlpn(network), argv[2]);
    CryptoNote::P2pTransportConfig config;
    config.mode = CryptoNote::P2pTransportMode::Required;
    config.name = argv[2]; config.keyFile = argv[3];
    CryptoNote::P2pTransportContext profile(config, network);
    std::cout << "Network: " << profile.alpn() << "\nService: " << config.name
      << "\nSHA256-SPKI: " << profile.publicKeyFingerprint() << '\n';
    return 0;
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n'; return 1;
  }
}
