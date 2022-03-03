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
  MOCK_METHOD0(generateKeyPair, void());
  MOCK_CONST_METHOD0(getKeyShare, std::unique_ptr<folly::IOBuf>());
  MOCK_CONST_METHOD1(
      generateSharedSecret,
      std::unique_ptr<folly::IOBuf>(folly::ByteRange keyShare));
  MOCK_CONST_METHOD0(clone, std::unique_ptr<KeyExchange>());

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
