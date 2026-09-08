// Compile the original inspected scanner in this translation unit so the
// prototype can reuse its private AEAD and ownership predicates verbatim.
// Nothing is patched in the source repository or linked into a wallet/node.
#include "crypto_pq/PqScan.cpp"
#include "prototype.h"

namespace CryptoPQ {
std::optional<PqOwnedOutput> reviewScanV2Only(
    const PqScanKeys& keys, const Hash256& ih, const PqScanOutput& out) {
  KemShared ss = kem_decaps(keys.viewSk, out.kemCt);
  Tools::SecretLock sharedLock(ss.data(), ss.size());
  const auto oc = outContext(ih, out.kemCt, out.outputIndex);
  if (auto payload = tryDecrypt(ss, oc, out))
    return finishOwned(keys.spendPub, out, *payload, oc);
  return std::nullopt;
}
}
