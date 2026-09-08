#include "prototype.h"
#include "crypto_pq/PqOutputBuilder.h"
#include "crypto_pq/PqSeed.h"
#include "crypto_pq/PqAead.h"
#include "gtest/gtest.h"
#include <array>
#include <cstring>

using namespace CryptoPQ;
namespace {
SeedMaster testSeed(uint8_t value) { SeedMaster s{}; s.fill(value); return s; }
struct Fixture {
  std::pair<KemPublicKey, KemSecretKey> view = deriveViewKeys(testSeed(7));
  std::pair<DsaPublicKey, DsaSecretKey> spend = deriveSpendKeys(testSeed(7));
  Hash256 ih{};
  PqScanKeys keys() const { return {view.second, spend.first}; }
  PqScanOutput current(uint64_t t) const {
    auto b = buildPqOutput(view.first, spend.first, ih, 2, 123, t);
    return {2, 123, b.kemCt, b.encPayload, b.spendCommit};
  }
  // Historical compatibility vector only; this test cannot encode a wire
  // transaction or submit outputs to any daemon.
  PqScanOutput historicalZero() const {
    auto k = kem_encaps(view.first);
    Rho rho{}; rho.fill(3);
    auto oc = legacyOutContextV1(ih, k.first, 2, 0);
    std::array<uint8_t, 40> aad{}, plain{};
    std::memcpy(aad.data(), oc.data(), 32); aad[32] = 123;
    std::memcpy(plain.data(), rho.data(), 32);
    AeadNonce nonce{};
    auto payload = aead_encrypt(deriveAeadKey(k.second, oc), nonce,
      aad.data(), aad.size(), plain.data(), plain.size());
    return {2, 123, k.first, payload, spendCommit(spend.first, rho)};
  }
};
}

TEST(ReviewV2Only, CurrentRoutingIndicesPreserveExactRecords) {
  Fixture f;
  for (uint64_t t : {0ull, 1ull, 44ull, 259ull, 4095ull, 0xffffffffull}) {
    const auto o = f.current(t);
    auto actual = reviewScanV2Only(f.keys(), f.ih, o);
    auto baseline = scanPqOutputWithLegacyTWindow(f.keys(), f.ih, o, 64);
    ASSERT_TRUE(actual); ASSERT_TRUE(baseline);
    EXPECT_EQ(actual->subaddrIndexT, t);
    EXPECT_EQ(actual->rho, baseline->rho);
    EXPECT_EQ(actual->amount, baseline->amount);
    EXPECT_EQ(actual->outContext, baseline->outContext);
    EXPECT_EQ(actual->outputIndex, baseline->outputIndex);
  }
}
TEST(ReviewV2Only, HistoricalZeroDistinguishesOneFromV2Only) {
  Fixture f; auto o = f.historicalZero();
  EXPECT_TRUE(scanPqOutputWithLegacyTWindow(f.keys(), f.ih, o, 1));
  EXPECT_FALSE(reviewScanV2Only(f.keys(), f.ih, o));
  EXPECT_TRUE(scanPqOutputWithLegacyTWindow(f.keys(), f.ih, o, 64));
}
TEST(ReviewV2Only, ForeignOutputDoesNotCredit) {
  Fixture f; auto o = f.current(4095);
  auto other = f.keys(); other.viewSk = deriveViewKeys(testSeed(9)).second;
  EXPECT_FALSE(reviewScanV2Only(other, f.ih, o));
}
TEST(ReviewV2Only, WrongSpendAuthorityDoesNotCredit) {
  Fixture f; auto o = f.current(1);
  auto other = f.keys(); other.spendPub = deriveSpendKeys(testSeed(9)).first;
  EXPECT_FALSE(reviewScanV2Only(other, f.ih, o));
}
TEST(ReviewV2Only, PayloadIntegrityFailureDoesNotCredit) {
  Fixture f; auto original = f.current(259); auto o = original;
  o.encPayload.back() ^= 1;
  EXPECT_FALSE(reviewScanV2Only(f.keys(), f.ih, o));
  EXPECT_TRUE(reviewScanV2Only(f.keys(), f.ih, original));
}
TEST(ReviewV2Only, AmountBindingFailureDoesNotCredit) {
  Fixture f; auto o = f.current(259); ++o.amount;
  EXPECT_FALSE(reviewScanV2Only(f.keys(), f.ih, o));
}
TEST(ReviewV2Only, SpendCommitBindingFailureDoesNotCredit) {
  Fixture f; auto o = f.current(259); o.spendCommit[0] ^= 1;
  EXPECT_FALSE(reviewScanV2Only(f.keys(), f.ih, o));
}
TEST(ReviewV2Only, OutputIndexAndInputsHashAreBound) {
  Fixture f; auto original = f.current(1); auto o = original; ++o.outputIndex;
  EXPECT_FALSE(reviewScanV2Only(f.keys(), f.ih, o));
  auto wrong = f.ih; wrong[0] ^= 1;
  EXPECT_FALSE(reviewScanV2Only(f.keys(), wrong, original));
}
TEST(ReviewV2Only, RepeatedScansPreserveRecord) {
  Fixture f; auto o = f.current(4095);
  auto first = reviewScanV2Only(f.keys(), f.ih, o); ASSERT_TRUE(first);
  for (int i = 0; i < 3; ++i) {
    auto next = reviewScanV2Only(f.keys(), f.ih, o); ASSERT_TRUE(next);
    EXPECT_EQ(first->rho, next->rho); EXPECT_EQ(first->subaddrIndexT, next->subaddrIndexT);
  }
}
TEST(ReviewV2Only, ExistingSigningDigestBindsTransactionVersion) {
  // Hash-level check only; this does not make version 2 a valid wire format.
  UnsignedTx body;
  body.version = 1;
  auto first = txSigningDigest(body);
  body.version = 2;
  EXPECT_NE(first, txSigningDigest(body));
  body.version = 1;
  EXPECT_EQ(first, txSigningDigest(body));
}
int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
