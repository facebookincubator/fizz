/*
 *  Copyright (c) 2019-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/protocol/clock/Clock.h>
#include <folly/portability/GMock.h>

namespace fizz {
namespace test {

class MockClock : public Clock {
 public:
  MOCK_CONST_METHOD0(getCurrentTime, std::chrono::system_clock::time_point());
};

} // namespace test
} // namespace fizz
