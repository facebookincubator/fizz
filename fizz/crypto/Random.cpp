/*
 *  Copyright (c) Meta Platforms, Inc. and affiliates.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/crypto/Random.h>

#include <fizz/fizz-config.h>

#include <atomic>

#if defined(FIZZ_RANDOM_USE_OPENSSL) && FIZZ_RANDOM_USE_OPENSSL
#include <openssl/rand.h>
#include <limits>
#else
#include <sodium/randombytes.h>
#endif

namespace fizz {

namespace {
std::atomic<void (*)(unsigned char*, size_t)> randomForTesting{nullptr};
} // namespace

Status random(Error& err, unsigned char* out, size_t count) {
  if (count == 0) {
    return Status::Success;
  }
  if (!out) {
    return err.error("No buffer for random bytes");
  }
  if (auto fn = randomForTesting.load(std::memory_order_relaxed)) {
    fn(out, count);
    return Status::Success;
  }
#if defined(FIZZ_RANDOM_USE_OPENSSL) && FIZZ_RANDOM_USE_OPENSSL
  if (count > static_cast<size_t>(std::numeric_limits<int>::max()) ||
      RAND_bytes(out, static_cast<int>(count)) != 1) {
    return err.error("Could not generate random bytes");
  }
#else
  randombytes_buf(out, count);
#endif
  return Status::Success;
}

namespace detail {
void setRandomForTesting(void (*fn)(unsigned char* out, size_t count)) {
  randomForTesting.store(fn, std::memory_order_relaxed);
}
} // namespace detail

} // namespace fizz
