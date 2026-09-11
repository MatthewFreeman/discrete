#pragma once
#if defined(DISCRETE_PQ_P2P)
#include <string>
#include <openssl/types.h>
namespace CryptoNote {
EVP_PKEY* loadP2pTransportKey(const std::string& path, const std::string& alpn, const std::string& name);
void createP2pTransportKey(const std::string& path, const std::string& alpn, const std::string& name);
}
#endif
