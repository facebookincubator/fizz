/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>

#include <fizz/crypto/openssl/OpenSSLKeyUtils.h>
#include <fizz/crypto/test/TestUtil.h>

#include <folly/String.h>


namespace fizz {
namespace test {

TEST(ValidateECKey, GoodPrivateKey) {
  auto key = getPrivateKey(kP256Key);
  detail::validateECKey(key, NID_X9_62_prime256v1);
}

TEST(ValidateECKey, GoodPubicKey) {
  auto key = getPublicKey(kP256PublicKey);
  detail::validateECKey(key, NID_X9_62_prime256v1);
}

TEST(ValidateECKey, WrongKeyType) {
  auto key = getPrivateKey(kRSAKey);
  EXPECT_THROW(
      detail::validateECKey(key, NID_X9_62_prime256v1), std::runtime_error);
}

TEST(ValidateECKey, WrongCurve) {
  auto key = getPrivateKey(kP256Key);
  EXPECT_THROW(
      detail::validateECKey(key, NID_X9_62_prime239v3), std::runtime_error);
}
} // namespace test
} // namespace fizz
