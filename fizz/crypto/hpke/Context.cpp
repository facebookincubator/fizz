/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/crypto/hpke/Context.h>
#include <fizz/crypto/hpke/Utils.h>

namespace fizz {
namespace hpke {

HpkeContext::HpkeContext(
    std::unique_ptr<Aead> cipher,
    std::unique_ptr<folly::IOBuf> exporterSecret,
    std::unique_ptr<fizz::hpke::Hkdf> hkdf,
    HpkeSuiteId suiteId)
    : cipher_(std::move(cipher)),
      exporterSecret_(std::move(exporterSecret)),
      hkdf_(std::move(hkdf)),
      suiteId_(std::move(suiteId)) {}

void HpkeContext::incrementSeq() {
  if (seqNum_ >= (UINT64_MAX - 1)) {
    throw std::runtime_error("NonceOverflowError: When incrementing seqNum");
  }
  seqNum_ += 1;
}

std::unique_ptr<folly::IOBuf> HpkeContext::seal(
    const folly::IOBuf* aad,
    std::unique_ptr<folly::IOBuf> pt) {
  std::unique_ptr<folly::IOBuf> ct =
      cipher_->encrypt(std::move(pt), aad, seqNum_);
  incrementSeq();
  return ct;
}

std::unique_ptr<folly::IOBuf> HpkeContext::open(
    const folly::IOBuf* aad,
    std::unique_ptr<folly::IOBuf> ct) {
  std::unique_ptr<folly::IOBuf> pt =
      cipher_->decrypt(std::move(ct), aad, seqNum_);
  incrementSeq();
  return pt;
}

std::unique_ptr<folly::IOBuf> HpkeContext::exportSecret(
    std::unique_ptr<folly::IOBuf> exporterContext,
    size_t desiredLength) const {
  auto maxL = 255 * hkdf_->hashLength();
  if (desiredLength > maxL) {
    throw std::runtime_error(
        "desired length for exported secret exceeds maximum");
  }
  return hkdf_->labeledExpand(
      exporterSecret_->coalesce(),
      folly::ByteRange(folly::StringPiece("sec")),
      std::move(exporterContext),
      desiredLength,
      suiteId_->clone());
}

std::unique_ptr<folly::IOBuf> HpkeContext::getExporterSecret() {
  return exporterSecret_->clone();
}

} // namespace hpke
} // namespace fizz
