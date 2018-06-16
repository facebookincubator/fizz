/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/aead/AESGCM128.h>
#include <fizz/crypto/aead/Aead.h>
#include <fizz/crypto/aead/IOBufUtil.h>
#include <folly/Conv.h>
#include <folly/Memory.h>
#include <folly/Range.h>
#include <folly/String.h>
#include <folly/lang/Bits.h>
#include <glog/logging.h>
#include <openssl/evp.h>

namespace fizz {

/**
 * Aead implementation using an OpenSSL EvpCipher.
 *
 * The template struct requires the following parameters:
 *   - Cipher: function returning EVP_CIPHER*
 *   - kKeyLength: length of key required
 *   - kIvLength: length of iv required
 *   - kTagLength: authentication tag length
 */
template <typename EVPImpl>
class OpenSSLEVPCipher : public Aead {
  static_assert(EVPImpl::kIVLength >= sizeof(uint64_t), "iv too small");

 public:
  OpenSSLEVPCipher();
  ~OpenSSLEVPCipher() override = default;

  OpenSSLEVPCipher(OpenSSLEVPCipher&& other) = default;
  OpenSSLEVPCipher& operator=(OpenSSLEVPCipher&& other) = default;

  void setKey(TrafficKey trafficKey) override;

  size_t keyLength() const override {
    return EVPImpl::kKeyLength;
  }

  size_t ivLength() const override {
    return EVPImpl::kIVLength;
  }

  std::unique_ptr<folly::IOBuf> encrypt(
      std::unique_ptr<folly::IOBuf>&& plaintext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override;

  folly::Optional<std::unique_ptr<folly::IOBuf>> tryDecrypt(
      std::unique_ptr<folly::IOBuf>&& ciphertext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override;

  size_t getCipherOverhead() const override;

 private:
  std::array<uint8_t, EVPImpl::kIVLength> createIV(uint64_t seqNum) const;

  using CipherCtxDeleter =
      folly::static_function_deleter<EVP_CIPHER_CTX, &EVP_CIPHER_CTX_free>;

  TrafficKey trafficKey_;

  std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter> encryptCtx_;
  std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter> decryptCtx_;
};
} // namespace fizz
#include <fizz/crypto/aead/OpenSSLEVPCipher-inl.h>
