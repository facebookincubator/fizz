/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/Hkdf.h>
#include <fizz/record/Types.h>

namespace fizz {

/**
 * Interface for common TLS 1.3 key derivation functions.
 */
class KeyDerivation {
 public:
  virtual ~KeyDerivation() = default;

  virtual size_t hashLength() const = 0;

  /**
   * Returns the hash of a blank input (ie Hash("")).
   */
  virtual folly::ByteRange blankHash() const = 0;

  virtual Buf expandLabel(
      folly::ByteRange secret,
      folly::StringPiece label,
      Buf hashValue,
      uint16_t length) = 0;

  virtual std::vector<uint8_t> deriveSecret(
      folly::ByteRange secret,
      folly::StringPiece label,
      folly::ByteRange messageHash) = 0;

  /**
   * Performs HDKF expansion.
   */
  virtual Buf
  hkdfExpand(folly::ByteRange secret, Buf info, uint16_t length) = 0;

  virtual std::vector<uint8_t> hkdfExtract(
      folly::ByteRange salt,
      folly::ByteRange ikm) = 0;

  virtual void hash(const folly::IOBuf& in, folly::MutableByteRange out) = 0;

  virtual void hmac(
      folly::ByteRange key,
      const folly::IOBuf& in,
      folly::MutableByteRange out) = 0;
};

template <typename Hash>
class KeyDerivationImpl : public KeyDerivation {
 public:
  ~KeyDerivationImpl() override = default;

  KeyDerivationImpl(const std::string& labelPrefix);

  size_t hashLength() const override {
    return Hash::HashLen;
  }

  void hash(const folly::IOBuf& in, folly::MutableByteRange out) override {
    Hash::hash(in, out);
  }

  void hmac(
      folly::ByteRange key,
      const folly::IOBuf& in,
      folly::MutableByteRange out) override {
    Hash::hmac(key, in, out);
  }

  folly::ByteRange blankHash() const override {
    return Hash::BlankHash;
  }

  Buf expandLabel(
      folly::ByteRange secret,
      folly::StringPiece label,
      Buf hashValue,
      uint16_t length) override;

  std::vector<uint8_t> deriveSecret(
      folly::ByteRange secret,
      folly::StringPiece label,
      folly::ByteRange messageHash) override;

  virtual Buf hkdfExpand(folly::ByteRange secret, Buf info, uint16_t length)
      override;

  std::vector<uint8_t> hkdfExtract(folly::ByteRange salt, folly::ByteRange ikm)
      override {
    return HkdfImpl<Hash>().extract(salt, ikm);
  }

 private:
  std::string labelPrefix_;
};
} // namespace fizz

#include <fizz/crypto/KeyDerivation-inl.h>
