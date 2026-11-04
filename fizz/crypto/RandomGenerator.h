/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

// TODO: Deprecate this.
#pragma once

#include <fizz/crypto/Random.h>
#include <fizz/util/Status.h>
#include <folly/io/IOBuf.h>
#include <array>

namespace fizz {

namespace detail {
inline void randomBytes(void* out, size_t len) {
  Error err;
  FIZZ_THROW_ON_ERROR(
      fizz::random(err, static_cast<unsigned char*>(out), len), err);
}
} // namespace detail

template <size_t Size>
struct RandomGenerator {
  /**
   * Returns an array of random data.
   */
  std::array<uint8_t, Size> generateRandom() {
    std::array<uint8_t, Size> random;
    detail::randomBytes(random.data(), Size);
    return random;
  }
};

template <typename T, typename = std::enable_if_t<std::is_integral<T>::value>>
struct RandomNumGenerator {
  /**
   * Fills a POD type T with random data.
   */
  T generateRandom() {
    T random;
    detail::randomBytes(&random, sizeof(random));
    return random;
  }
};

struct RandomBufGenerator {
  explicit RandomBufGenerator(size_t c) : count(c) {}
  std::unique_ptr<folly::IOBuf> generateRandom() {
    auto random = folly::IOBuf::create(count);
    if (count > 0) {
      detail::randomBytes(random->writableData(), count);
      random->append(count);
    }
    return random;
  }
  size_t count;
};

} // namespace fizz
