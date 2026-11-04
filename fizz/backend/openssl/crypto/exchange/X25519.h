/*
 *  Copyright (c) Meta Platforms, Inc. and affiliates.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/exchange/KeyExchange.h>

#include <folly/Range.h>
#include <folly/io/IOBuf.h>
#include <folly/ssl/OpenSSLPtrTypes.h>

namespace fizz::openssl {

class X25519KeyExchange : public KeyExchange {
 public:
  ~X25519KeyExchange() override = default;
  Status generateKeyPair(Error& err) override;
  Status getKeyShare(std::unique_ptr<folly::IOBuf>& ret, Error& err)
      const override;
  Status generateSharedSecret(
      std::unique_ptr<folly::IOBuf>& ret,
      Error& err,
      folly::ByteRange keyShare) const override;
  Status clone(std::unique_ptr<KeyExchange>& ret, Error& err) const override;
  std::size_t getExpectedKeyShareSize() const override;

  Status setPrivateKey(Error& err, std::unique_ptr<folly::IOBuf> gotPrivKey);

 private:
  static constexpr size_t kKeySize = 32;

  folly::ssl::EvpPkeyUniquePtr key_;
};

} // namespace fizz::openssl
