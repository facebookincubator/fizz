/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <fizz/server/SlidingBloomReplayCache.h>

#include <folly/Random.h>

#include <unordered_set>

using namespace folly;

namespace fizz {
namespace server {
namespace test {

static std::string generateRandomString(size_t minimum, size_t maximum) {
  size_t length = Random::rand64(minimum, maximum + 1);
  auto randchar = []() -> char {
    const char kCharset[] =
        "0123456789+/=-_"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    return kCharset[Random::rand64(0, sizeof(kCharset))];
  };
  std::string str(length, 0);
  std::generate_n(str.begin(), length, randchar);
  return str;
}

static folly::ByteRange toRange(const std::string& str) {
  return folly::ByteRange(folly::StringPiece(str));
}

TEST(SlidingBloomReplayCacheTest, TestSimpleGetSet) {
  const int numTries = 1 << 14;
  SlidingBloomReplayCache cache(12, numTries, 0.0005, nullptr);
  std::vector<std::string> history(numTries);
  for (size_t i = 0; i < numTries; i++) {
    history[i] = generateRandomString(8, 64);
    EXPECT_FALSE(cache.test(toRange(history[i])));
  }
  for (size_t i = 0; i < numTries; i++) {
    cache.set(toRange(history[i]));
    EXPECT_TRUE(cache.test(toRange(history[i])));
  }
}

TEST(SlidingBloomReplayCacheTest, TestSimpleTestAndSet) {
  const int numTries = 1 << 14;
  SlidingBloomReplayCache cache(12, numTries, 0.0005, nullptr);
  std::vector<std::string> history(numTries);
  size_t falsePositives = 0;
  for (size_t i = 0; i < numTries; i++) {
    history[i] = generateRandomString(8, 64);
    if (cache.testAndSet(toRange(history[i]))) {
      falsePositives++;
    }
  }

  for (size_t i = 0; i < numTries; i++) {
    EXPECT_TRUE(cache.test(toRange(history[i])));
  }

  double actualErrorRate = static_cast<double>(falsePositives) / numTries;
  EXPECT_LT(actualErrorRate, 0.0005);
}

TEST(SlidingBloomReplayCacheTest, TestCacheErrorRate) {
  const int numTries = 1 << 14;
  SlidingBloomReplayCache cache(12, numTries, 0.0001, nullptr);
  std::vector<std::string> history(numTries);
  for (size_t i = 0; i < numTries; i++) {
    history[i] = generateRandomString(8, 64);
    cache.set(toRange(history[i]));
  }

  size_t falsePositives = 0;
  std::unordered_set<std::string> seen(history.begin(), history.end());

  for (size_t i = 0; i < numTries; i++) {
    std::string needle;
    do {
      needle = generateRandomString(8, 64);
    } while (seen.count(needle) == 1);
    seen.insert(needle);
    if (cache.test(toRange(needle))) {
      falsePositives++;
    }
  }

  double actualErrorRate = static_cast<double>(falsePositives) / numTries;
  EXPECT_LT(actualErrorRate, 0.001);
}

TEST(SlidingBloomReplayCacheTest, TestTimeBucketing) {
  const int numTries = 1 << 14;

  folly::EventBase evb;
  SlidingBloomReplayCache cache(12, numTries, 0.0005, &evb);

  std::vector<std::string> history(numTries);
  for (size_t i = 0; i < numTries; i++) {
    history[i] = generateRandomString(8, 64);
    cache.set(toRange(history[i]));
  }

  // 6 seconds in, all values should still be set
  evb.scheduleAt(
      [&] {
        for (int i = 0; i < numTries; ++i) {
          EXPECT_TRUE(cache.test(toRange(history[i])));
        }
      },
      evb.now() + std::chrono::seconds(6));

  // 13 seconds in, all should be gone.
  evb.scheduleAt(
      [&] {
        for (int i = 0; i < numTries; ++i) {
          EXPECT_FALSE(cache.test(toRange(history[i])));
        }
        evb.terminateLoopSoon();
      },
      evb.now() + std::chrono::seconds(13));
  evb.loop();
}
} // namespace test
} // namespace server
} // namespace fizz
