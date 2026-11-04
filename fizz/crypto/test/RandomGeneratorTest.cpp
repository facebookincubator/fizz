/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>

#include <fizz/crypto/Random.h>
#include <fizz/crypto/RandomGenerator.h>

#include <fizz/crypto/test/TestUtil.h>

namespace fizz {
namespace test {

TEST(RandomGeneratorTest, TestRandom) {
  useMockRandom();

  auto random = RandomGenerator<32>().generateRandom();
  std::array<uint8_t, 32> expected;
  expected.fill(0x44);
  EXPECT_EQ(random, expected);
}

TEST(RandomGeneratorTest, TestRandomUInt32) {
  useMockRandom();

  auto random = RandomNumGenerator<uint32_t>().generateRandom();
  EXPECT_EQ(random, 0x44444444);
}

TEST(RandomGeneratorTest, TestRandomBuf) {
  useMockRandom();
  auto random = RandomBufGenerator(32).generateRandom();
  auto expected = folly::IOBuf::create(32);
  memset(expected->writableData(), 0x44, 32);
  expected->append(32);
  EXPECT_TRUE(folly::IOBufEqualTo()(random, expected));
}

TEST(RandomTest, DefaultSource) {
  fizz::detail::setRandomForTesting(nullptr);
  std::array<unsigned char, 32> a{};
  std::array<unsigned char, 32> b{};
  Error err;
  ASSERT_EQ(random(err, a.data(), a.size()), Status::Success);
  ASSERT_EQ(random(err, b.data(), b.size()), Status::Success);
  EXPECT_NE(a, b);
}

TEST(RandomTest, Override) {
  useMockRandom();
  std::array<unsigned char, 4> out{};
  Error err;
  ASSERT_EQ(random(err, out.data(), out.size()), Status::Success);
  EXPECT_EQ(out, (std::array<unsigned char, 4>{0x44, 0x44, 0x44, 0x44}));
  fizz::detail::setRandomForTesting(nullptr);
}
} // namespace test
} // namespace fizz
