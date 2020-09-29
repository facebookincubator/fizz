/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/aead/OpenSSLEVPCipher.h>
#include <fizz/crypto/Hpke.h>

namespace fizz {
namespace hpke {

class HpkeContext {
 public:
  HpkeContext(std::unique_ptr<Aead> cipher, folly::ByteRange exporterSecret, std::unique_ptr<fizz::hpke::Hkdf> hkdf);
  std::unique_ptr<folly::IOBuf> seal(const folly::IOBuf* aad, std::unique_ptr<folly::IOBuf> pt);
  std::unique_ptr<folly::IOBuf> open(const folly::IOBuf *aad, std::unique_ptr<folly::IOBuf> ct);

 private:
  void incrementSeq();
  uint64_t seqNum_{0};
  std::unique_ptr<Aead> cipher_;
  folly::ByteRange exporterSecret_;
  std::unique_ptr<fizz::hpke::Hkdf> hkdf_;
};

} // namespace hpke
} // namespace fizz
