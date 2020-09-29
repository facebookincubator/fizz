/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/crypto/HpkeContext.h>

namespace fizz {
namespace hpke {
  HpkeContext::HpkeContext(std::unique_ptr<Aead> cipher, folly::ByteRange exporterSecret, std::unique_ptr<fizz::hpke::Hkdf> hkdf) {
    cipher_ = std::move(cipher);
    exporterSecret_ = exporterSecret;
    hkdf_ = std::move(hkdf);
  }

  void HpkeContext::incrementSeq() {
    if (seqNum_ >= (UINT64_MAX - 1)) {
      throw std::runtime_error("NonceOverflowError: When incrementing seqNum");
    }
    seqNum_ += 1;
  }

  std::unique_ptr<folly::IOBuf> HpkeContext::seal(const folly::IOBuf* aad, std::unique_ptr<folly::IOBuf> pt) {
    std::unique_ptr<folly::IOBuf> ct = cipher_->encrypt(std::move(pt), aad, seqNum_);
    incrementSeq();
    return ct;
  }

  std::unique_ptr<folly::IOBuf> HpkeContext::open(const folly::IOBuf *aad, std::unique_ptr<folly::IOBuf> ct) {
    std::unique_ptr<folly::IOBuf> pt = cipher_->decrypt(std::move(ct), aad, seqNum_);
    incrementSeq();
    return pt;
  }

} // namespace hpke
} // namespace fizz
