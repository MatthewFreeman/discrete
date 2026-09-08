#pragma once
#include "crypto_pq/PqScan.h"

// Review-only receiver primitive. No node, wire encoder, signing or broadcast.
// The final consensus integration must select this by authenticated tx version.
namespace CryptoPQ {
std::optional<PqOwnedOutput> reviewScanV2Only(
    const PqScanKeys&, const Hash256&, const PqScanOutput&);
}
