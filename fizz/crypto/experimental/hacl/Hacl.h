/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */
#pragma once

#include <fizz/crypto/aead/Aead.h>

namespace fizz {
namespace hacl {

class Hacl : public Aead {
 public:
  size_t keyLength() const override {
    return 16;
  }

  size_t ivLength() const override {
    return 12;
  }

  void setEncryptedBufferHeadroom(size_t headroom) override {
    headroom_ = headroom;
  }

  void setKey(TrafficKey trafficKey) override;

  std::unique_ptr<folly::IOBuf> encrypt(
      std::unique_ptr<folly::IOBuf>&& plaintext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override;

  folly::Optional<std::unique_ptr<folly::IOBuf>> tryDecrypt(
      std::unique_ptr<folly::IOBuf>&& ciphertext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override;

  size_t getCipherOverhead() const override {
    return 16;
  }

  std::array<uint8_t, 12> createIV(uint64_t seqNum) const;

 private:
  size_t headroom_{5};
  TrafficKey key_;
};

} // namespace hacl
} // namespace fizz
