/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

namespace fizz {

/**
 * Interface for HMAC implementation.
 */
class Hmac {
 public:
  virtual ~Hmac() = default;

  /**
   * Length of the output.
   */
  virtual size_t length() const = 0;

  /**
   * Compute the hmac of in using key. Out must be able to hold length() bytes.
   */
  virtual void hmac(
      folly::ByteRange key,
      const folly::IOBuf& in,
      folly::MutableByteRange out) const = 0;
};

template <typename Hash>
class HmacImpl : public Hmac {
 public:
  size_t length() const override {
    return Hash::HashLen;
  }

  void hmac(
      folly::ByteRange key,
      const folly::IOBuf& in,
      folly::MutableByteRange out) const override {
    return Hash::hmac(key, in, out);
  }
}
} // namespace fizz
