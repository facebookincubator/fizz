/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/exchange/KeyExchange.h>
#include <fizz/crypto/openssl/OpenSSLKeyUtils.h>
#include <folly/ssl/OpenSSLPtrTypes.h>
#include <fizz/crypto/exchange/OpenSSLKeyExchange-inl.h>

namespace fizz {

/**
 * Eliptic curve key exchange implementation using OpenSSL.
 *
 * The template struct requires the following parameters:
 *   - curveNid: OpenSSL NID for the named curve
 */
template <class T>
class OpenSSLKeyExchange : public KeyExchange {
 public:
  ~OpenSSLKeyExchange() override = default;

  void generateKeyPair() override {
    keyExchange_.generateKeyPair();
  }

  std::unique_ptr<folly::IOBuf> getKeyShare() const override {
    const auto& key = keyExchange_.getKey();
    if (!key) {
      throw std::runtime_error("Key not initialized");
    }
    return detail::OpenSSLECKeyEncoder::encode(key);
  }

  std::unique_ptr<folly::IOBuf> generateSharedSecret(
      folly::ByteRange keyShare) const override {
    auto key = detail::OpenSSLECKeyDecoder<T>::decode(keyShare);
    return generateSharedSecret(key);
  }

  std::unique_ptr<folly::IOBuf> generateSharedSecret(
      const folly::ssl::EvpPkeyUniquePtr& peerKey) const {
    return keyExchange_.generateSharedSecret(peerKey);
  }

 private:
  detail::OpenSSLECKeyExchange<T> keyExchange_;
};
} // namespace fizz
