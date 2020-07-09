/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <fizz/tool/FizzCommandCommon.h>
#include <folly/container/Array.h>

namespace fizz {
namespace tool {
namespace test {

TEST(FizzCommandCommonTest, TestValidHostPortFromString) {
  struct ExpectedValues {
    std::string input;
    std::string host;
    uint16_t port;
  };
  auto results = folly::make_array(
      ExpectedValues{"www.example.com:80", "www.example.com", 80},
      ExpectedValues{"[::1]:80", "::1", 80},
      ExpectedValues{"127.0.0.1:80", "127.0.0.1", 80});
  for (auto result : results) {
    std::string host;
    uint16_t port;
    std::tie(host, port) = hostPortFromString(result.input);
    ASSERT_EQ(result.host, host);
    ASSERT_EQ(result.port, port);
  }
}

TEST(FizzCommandCommonTest, TestInvalidV6HostPortFromString) {
  auto inputs = folly::make_array("::1:80", "[::1:80", "::1]:80");
  for (auto input : inputs) {
    ASSERT_THROW(hostPortFromString(input), std::runtime_error);
  }
}

TEST(FizzCommandCommonTest, TestMissingPortHostPortFromString) {
  auto inputs =
      folly::make_array("www.example.com", "127.0.0.1", "[::1]", "::1");
  for (auto input : inputs) {
    ASSERT_THROW(hostPortFromString(input), std::runtime_error);
  }
}

} // namespace test
} // namespace tool
} // namespace fizz
