// Copyright (c) 2026, The Discrete developers
// Unit-level policy tests only: these empty transactions are not chain-valid.
// A deliberately permissive validator isolates the pool's height contract.
#include "gtest/gtest.h"
#include "ICoreStub.h"
#include "CryptoNoteCore/TransactionPool.h"
#include "Logging/ConsoleLogger.h"

using namespace CryptoNote;
namespace {
struct PolicyCore : ICoreStub {
  uint32_t height = 99;
  uint32_t getCurrentBlockchainHeight() override { return height; }
  bool getPqTransactionFee(const Transaction&, uint64_t& fee) override { fee = 1; return true; }
  bool check_tx_fee(const Transaction&, const Crypto::Hash&, size_t,
      tx_verification_context&, uint32_t) override { return true; }
};
struct PolicyValidator : ITransactionValidator {
  size_t readinessChecks = 0;
  bool ready = true;
  bool checkTransactionInputs(const Transaction&, BlockInfo&) override { return true; }
  bool checkTransactionInputs(const Transaction&, BlockInfo&, BlockInfo&) override {
    ++readinessChecks;
    return ready;
  }
  bool haveSpentKeyImages(const Transaction&) override { return false; }
  bool checkTransactionSize(size_t) override { return true; }
};
struct PolicyTime : ITimeProvider { time_t now() override { return 1000; } };

class PqDeliveryPool : public ::testing::Test {
protected:
  Logging::ConsoleLogger logger{Logging::ERROR};
  Currency currency = CurrencyBuilder(logger).testnet(true).pqDeliveryV2Height(100).currency();
  PolicyCore core;
  PolicyValidator validator;
  PolicyTime time;
  tx_memory_pool pool{currency, validator, core, time, logger};
  std::vector<Crypto::Hash> ids;
  void add(uint8_t type) {
    Transaction tx{};
    tx.version = TRANSACTION_VERSION_1;
    tx.txType = type;
    Crypto::Hash id{};
    id.data[0] = static_cast<uint8_t>(ids.size()+1);
    tx_verification_context tvc{};
    ASSERT_TRUE(pool.add_tx(tx, id, 100, tvc, false));
    ASSERT_TRUE(tvc.m_added_to_pool);
    ids.push_back(id);
  }
  void expectDifference(const std::vector<Crypto::Hash>& expected) {
    std::vector<Crypto::Hash> added, deleted;
    pool.get_difference({}, added, deleted);
    EXPECT_EQ(added, expected);
    EXPECT_TRUE(deleted.empty());
  }
  void expectTemplate(const std::vector<Crypto::Hash>& expected) {
    Block block{};
    size_t size=0; uint64_t fee=0;
    ASSERT_TRUE(pool.fill_block_template(block, 1000000, 2000000, 0, size, fee));
    EXPECT_EQ(block.transactionHashes, expected);
    EXPECT_EQ(size, expected.size()*100);
    EXPECT_EQ(fee, expected.size());
  }
  void TearDown() override {
    // take_tx removes these hashes from the existing process-wide cache.
    for (const auto& id : ids) {
      Transaction tx{}; size_t size=0; uint64_t fee=0;
      EXPECT_TRUE(pool.take_tx(id, tx, size, fee));
    }
  }
};

TEST_F(PqDeliveryPool, CachedReadinessStillObeysEachEraAndRollback) {
  add(TX_PQ); add(TX_PQ_V2);
  ASSERT_EQ(ids.size(), 2u);
  for (uint32_t height : {99u,100u,101u,99u,100u}) {
    core.height=height;
    const auto id=ids[height<100 ? 0 : 1];
    expectDifference({id});
    expectTemplate({id});
  }
  // Each subtype was validated only in its first permitted era.
  EXPECT_EQ(validator.readinessChecks, 2u);
  EXPECT_EQ(pool.get_transactions_count(), 2u);
}

TEST_F(PqDeliveryPool, TemplateFirstKeepsPolicyAndRetryChecks) {
  core.height=100;
  add(TX_PQ_V2);
  ASSERT_EQ(ids.size(), 1u);
  validator.ready=false;
  expectTemplate({}); expectDifference({});
  validator.ready=true;
  expectTemplate({ids[0]});
  core.height=99;
  expectTemplate({}); expectDifference({});
  core.height=100;
  expectDifference({ids[0]});
  EXPECT_EQ(validator.readinessChecks, 3u);
}
} // namespace
