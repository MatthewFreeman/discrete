#include "P2pTransport.h"
#include <algorithm>
#include <stdexcept>

namespace CryptoNote {
namespace {
std::string canonicalEndpoint(const std::string& value) {
  const auto colon = value.find(':');
  if (colon == std::string::npos || value.find(':', colon + 1) != std::string::npos)
    throw std::invalid_argument("P2P transport endpoint must be numeric IPv4:port");
  const auto ip = System::Ipv4Address(value.substr(0, colon)).toDottedDecimal();
  const auto portText = value.substr(colon + 1);
  if (portText.empty() || portText.find_first_not_of("0123456789") != std::string::npos)
    throw std::invalid_argument("Invalid P2P transport port");
  const auto port = std::stoul(portText);
  if (port == 0 || port > 65535) throw std::invalid_argument("Invalid P2P transport port");
  const auto result = P2pTransportConfig::endpoint(ip, static_cast<uint16_t>(port));
  if (result != value) throw std::invalid_argument("P2P transport endpoint must use canonical IPv4:port");
  return result;
}
}

P2pTransportMode P2pTransportConfig::parseMode(const std::string& value) {
  if (value == "off") return P2pTransportMode::Off;
  if (value == "mixed") return P2pTransportMode::Mixed;
  if (value == "pq-required") return P2pTransportMode::Required;
  throw std::invalid_argument("P2P transport must be off, mixed or pq-required");
}

std::string P2pTransportConfig::endpoint(const std::string& ip, uint16_t port) {
  return System::Ipv4Address(ip).toDottedDecimal() + ":" + std::to_string(port);
}

bool P2pTransportConfig::validName(const std::string& value) {
  if (value.empty() || value.size() > 253) return false;
  size_t label = 0;
  char previous = '.';
  for (const char c : value) {
    if (c == '.') {
      if (!label || previous == '-') return false;
      label = 0;
    } else {
      if (!(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-') return false;
      if ((!label && c == '-') || ++label > 63) return false;
    }
    previous = c;
  }
  return label != 0 && previous != '-';
}

P2pTransportPin P2pTransportConfig::parsePin(const std::string& value, std::string& ep) {
  const auto first = value.find(',');
  const auto second = first == std::string::npos ? first : value.find(',', first + 1);
  if (second == std::string::npos || value.find(',', second + 1) != std::string::npos)
    throw std::invalid_argument("P2P pin must be IPv4:port,service-name,sha256-SPKI");
  ep = canonicalEndpoint(value.substr(0, first));
  P2pTransportPin pin;
  pin.name = value.substr(first + 1, second - first - 1);
  const auto hash = value.substr(second + 1);
  if (!validName(pin.name) || hash.size() != 64 || hash.find_first_not_of("0123456789abcdef") != std::string::npos)
    throw std::invalid_argument("P2P pin requires a canonical ASCII name and 64 lowercase hex digits");
  for (size_t i = 0; i < pin.sha256.size(); ++i)
    pin.sha256[i] = static_cast<uint8_t>(std::stoul(hash.substr(i * 2, 2), nullptr, 16));
  return pin;
}

void P2pTransportConfig::validate() const {
  if (mode == P2pTransportMode::Off && (!pins.empty() || !requiredPeers.empty() || !keyFile.empty() || !name.empty()))
    throw std::invalid_argument("P2P transport off conflicts with a secure peer or identity setting");
  if (keyFile.empty() != name.empty() || (!name.empty() && !validName(name)))
    throw std::invalid_argument("Persistent P2P identity requires both a key file and canonical service name");
  if (pins.size() + requiredPeers.size() > 1024) throw std::invalid_argument("Too many local P2P transport rules");
  for (const auto& entry : pins) {
    canonicalEndpoint(entry.first);
    if (!validName(entry.second.name)) throw std::invalid_argument("Invalid P2P pin name");
  }
  for (const auto& ep : requiredPeers) canonicalEndpoint(ep);
}

bool P2pTransportConfig::requiresPq(const std::string& ep) const {
  return mode == P2pTransportMode::Required || pins.count(ep) != 0 ||
    std::find(requiredPeers.begin(), requiredPeers.end(), ep) != requiredPeers.end();
}

bool P2pTransportConfig::permitsFallback(const std::string& ep, bool inheritedPq) const {
  return mode == P2pTransportMode::Mixed && !inheritedPq && !requiresPq(ep);
}

std::string P2pTransportContext::networkAlpn(const boost::uuids::uuid& network) {
  static const char hex[] = "0123456789abcdef";
  std::string result = "discrete-p2p/1/";
  for (const auto byte : network) {
    result += hex[byte >> 4];
    result += hex[byte & 15];
  }
  return result;
}
}
