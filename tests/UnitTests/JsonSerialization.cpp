#include "gtest/gtest.h"

#include "Common/JsonValue.h"
#include "Rpc/CoreRpcServerCommandsDefinitions.h"
#include "Serialization/JsonOutputStreamSerializer.h"

using namespace CryptoNote;

namespace {

Common::JsonValue poolJson(const std::vector<BinaryArray>& transactions) {
  COMMAND_RPC_GET_POOL_CHANGES::response response{};
  response.isTailBlockActual = false;
  response.addedTxs = transactions;
  response.status = CORE_RPC_STATUS_OK;
  JsonOutputStreamSerializer serializer;
  response.serialize(serializer);
  return Common::JsonValue::fromString(serializer.getValue().toString());
}

}

TEST(JsonOutputSerializer, EmptyPoolResponse) {
  const auto json = poolJson({});
  EXPECT_EQ(0u, json("addedTxs").size());
  EXPECT_EQ("", json("deletedTxsIds").getString());
  EXPECT_EQ("OK", json("status").getString());
  EXPECT_FALSE(json("isTailBlockActual").getBool());
}

TEST(JsonOutputSerializer, NonemptyPoolPreservesCompleteByteArrays) {
  const std::vector<BinaryArray> bytes{{0, 1, 127, 128, 255}, {42, 0, 254}};
  const auto json = poolJson(bytes);
  ASSERT_EQ(bytes.size(), json("addedTxs").size());
  for (size_t i = 0; i < bytes.size(); ++i) {
    ASSERT_EQ(bytes[i].size(), json("addedTxs")[i].size());
    for (size_t j = 0; j < bytes[i].size(); ++j)
      EXPECT_EQ(bytes[i][j], json("addedTxs")[i][j].getInteger());
  }
  EXPECT_EQ("OK", json("status").getString());
}

TEST(JsonOutputSerializer, EmptyNestedArraysAndFollowingSiblings) {
  const auto json = poolJson({{}, {7}, {}, {8, 9}});
  ASSERT_EQ(4u, json("addedTxs").size());
  EXPECT_EQ(0u, json("addedTxs")[0].size());
  EXPECT_EQ(7, json("addedTxs")[1][0].getInteger());
  EXPECT_EQ(0u, json("addedTxs")[2].size());
  EXPECT_EQ(9, json("addedTxs")[3][1].getInteger());
  EXPECT_EQ("", json("deletedTxsIds").getString());
}

TEST(JsonOutputSerializer, MultipleArrayLevelsAndObjectElements) {
  JsonOutputStreamSerializer serializer;
  size_t size = 1;
  ASSERT_TRUE(serializer.beginArray(size, "outer"));
  ASSERT_TRUE(serializer.beginArray(size, ""));
  ASSERT_TRUE(serializer.beginArray(size, ""));
  uint32_t value = 17;
  ASSERT_TRUE(serializer(value, ""));
  serializer.endArray();
  serializer.endArray();
  ASSERT_TRUE(serializer.beginObject(""));
  ASSERT_TRUE(serializer(value, "value"));
  ASSERT_TRUE(serializer.beginArray(size, "children"));
  ASSERT_TRUE(serializer(value, ""));
  serializer.endArray();
  serializer.endObject();
  serializer.endArray();
  ASSERT_TRUE(serializer(value, "sibling"));
  const auto json = Common::JsonValue::fromString(serializer.getValue().toString());
  EXPECT_EQ(17, json("outer")[0][0][0].getInteger());
  EXPECT_EQ(17, json("outer")[1]("value").getInteger());
  EXPECT_EQ(17, json("outer")[1]("children")[0].getInteger());
  EXPECT_EQ(17, json("sibling").getInteger());
}
