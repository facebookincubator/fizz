/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GMock.h>

#include <fizz/crypto/exchange/KeyExchange.h>

namespace fizz {

/* using override */
using namespace testing;

class MockKeyExchange : public KeyExchange {
 public:
  MOCK_METHOD(void, generateKeyPair, ());
  MOCK_METHOD(std::unique_ptr<folly::IOBuf>, getKeyShare, (), (const));
  MOCK_METHOD(
      std::unique_ptr<folly::IOBuf>,
      generateSharedSecret,
      (folly::ByteRange keyShare),
      (const));
  MOCK_METHOD(std::unique_ptr<KeyExchange>, clone, (), (const));

  void setDefaults() {
    ON_CALL(*this, getKeyShare()).WillByDefault(InvokeWithoutArgs([]() {
      return folly::IOBuf::copyBuffer("keyshare");
    }));
    ON_CALL(*this, generateSharedSecret(_))
        .WillByDefault(InvokeWithoutArgs(
            []() { return folly::IOBuf::copyBuffer("sharedsecret"); }));
  }
};

} // namespace fizz
