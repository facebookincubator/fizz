/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/exchange/KeyExchange.h>

#include <folly/Optional.h>
#include <folly/Range.h>
#include <folly/io/IOBuf.h>
#include <sodium.h>

namespace fizz {

/**
 * X25519 key exchange implementation using libsodium.
 */
class X25519KeyExchange : public KeyExchange {
 public:
  ~X25519KeyExchange() override = default;
  void generateKeyPair() override;
  std::unique_ptr<folly::IOBuf> getKeyShare() const override;
  std::unique_ptr<folly::IOBuf> generateSharedSecret(
      folly::ByteRange keyShare) const override;

 private:
  using PrivKey =
      std::array<uint8_t, crypto_scalarmult_SCALARBYTES>;
  using PubKey =
      std::array<uint8_t, crypto_scalarmult_BYTES>;

  folly::Optional<PrivKey> privKey_;
  folly::Optional<PubKey> pubKey_;
};
} // namespace fizz
