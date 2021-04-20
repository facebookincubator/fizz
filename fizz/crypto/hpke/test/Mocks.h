/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/aead/Aead.h>
#include <fizz/crypto/exchange/X25519.h>
#include <folly/portability/GMock.h>

namespace fizz {
namespace hpke {
namespace test {

class MockAeadCipher : public Aead {
 public:
  explicit MockAeadCipher(std::unique_ptr<Aead> actualCipher)
      : actualCipher_(std::move(actualCipher)) {}

  size_t keyLength() const override {
    return actualCipher_->keyLength();
  }

  size_t ivLength() const override {
    return actualCipher_->ivLength();
  }

  MOCK_CONST_METHOD0(getKey, folly::Optional<TrafficKey>());
  MOCK_METHOD1(_setKey, void(TrafficKey* key));
  void setKey(TrafficKey key) override {
    _setKey(&key);
    actualCipher_->setKey(std::move(key));
  }

  std::unique_ptr<folly::IOBuf> encrypt(
      std::unique_ptr<folly::IOBuf>&& plaintext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum,
      AeadOptions options) const override {
    return actualCipher_->encrypt(
        std::move(plaintext), associatedData, seqNum, options);
  }

  std::unique_ptr<folly::IOBuf> inplaceEncrypt(
      std::unique_ptr<folly::IOBuf>&& plaintext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override {
    return actualCipher_->inplaceEncrypt(
        std::move(plaintext), associatedData, seqNum);
  }

  void setEncryptedBufferHeadroom(size_t headroom) override {
    return actualCipher_->setEncryptedBufferHeadroom(headroom);
  }

  std::unique_ptr<folly::IOBuf> decrypt(
      std::unique_ptr<folly::IOBuf>&& ciphertext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum,
      AeadOptions options) const override {
    return actualCipher_->decrypt(
        std::move(ciphertext), associatedData, seqNum, options);
  }

  folly::Optional<std::unique_ptr<folly::IOBuf>> tryDecrypt(
      std::unique_ptr<folly::IOBuf>&& ciphertext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum,
      AeadOptions options) const override {
    return actualCipher_->tryDecrypt(
        std::move(ciphertext), associatedData, seqNum, options);
  }

  size_t getCipherOverhead() const override {
    return actualCipher_->getCipherOverhead();
  }

 private:
  std::unique_ptr<Aead> actualCipher_;
};

} // namespace test
} // namespace hpke
} // namespace fizz
