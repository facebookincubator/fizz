/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/aead/OpenSSLEVPCipher.h>
#include <fizz/crypto/hpke/Hkdf.h>

#include <fizz/crypto/hpke/Types.h>

#include <fizz/protocol/Types.h>

namespace fizz {
namespace hpke {

class HpkeContext {
 public:
  HpkeContext(
      std::unique_ptr<Aead> cipher,
      std::unique_ptr<folly::IOBuf> exporterSecret,
      std::unique_ptr<fizz::hpke::Hkdf> hkdf,
      HpkeSuiteId suiteId);
  std::unique_ptr<folly::IOBuf> seal(
      const folly::IOBuf* aad,
      std::unique_ptr<folly::IOBuf> pt);
  std::unique_ptr<folly::IOBuf> open(
      const folly::IOBuf* aad,
      std::unique_ptr<folly::IOBuf> ct);
  std::unique_ptr<folly::IOBuf> exportSecret(
      std::unique_ptr<folly::IOBuf> exporterContext,
      size_t desiredLength) const;
  // NOTE: This should only be used for testing.
  std::unique_ptr<folly::IOBuf> getExporterSecret();

 private:
  void incrementSeq();
  uint64_t seqNum_{0};
  std::unique_ptr<Aead> cipher_;
  std::unique_ptr<folly::IOBuf> exporterSecret_;
  std::unique_ptr<fizz::hpke::Hkdf> hkdf_;
  HpkeSuiteId suiteId_;
};

} // namespace hpke
} // namespace fizz
