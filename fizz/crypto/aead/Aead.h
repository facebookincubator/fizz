/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Optional.h>
#include <folly/io/IOBuf.h>

namespace fizz {

struct TrafficKey {
  std::unique_ptr<folly::IOBuf> key;
  std::unique_ptr<folly::IOBuf> iv;
};

/**
 * Interface for aead algorithms (RFC 5116).
 */
class Aead {
 public:
  virtual ~Aead() = default;

  /**
   * Returns the number of key bytes needed by this aead.
   */
  virtual size_t keyLength() const = 0;

  /**
   * Returns the number of iv bytes needed by this aead.
   */
  virtual size_t ivLength() const = 0;

  /**
   * Sets the key and iv for this aead. The length of the key and iv must match
   * keyLength() and ivLength().
   */
  virtual void setKey(TrafficKey key) = 0;

  /**
   * Encrypts plaintext. Will throw on error.
   */
  virtual std::unique_ptr<folly::IOBuf> encrypt(
      std::unique_ptr<folly::IOBuf>&& plaintext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const = 0;

  /**
   * Version of encrypt which is guaranteed to be inplace. Will throw an
   * exception if the inplace encryption cannot be done.
   */
  virtual std::unique_ptr<folly::IOBuf> inplaceEncrypt(
      std::unique_ptr<folly::IOBuf>&& plaintext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const = 0;

  /**
   * Set a hint to the AEAD about how much space to try to leave as headroom for
   * ciphertexts returned from encrypt.  Implementations may or may not honor
   * this.
   */
  virtual void setEncryptedBufferHeadroom(size_t headroom) = 0;

  /**
   * Decrypt ciphertext. Will throw if the ciphertext does not decrypt
   * successfully.
   */
  virtual std::unique_ptr<folly::IOBuf> decrypt(
      std::unique_ptr<folly::IOBuf>&& ciphertext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const {
    auto plaintext = tryDecrypt(
        std::forward<std::unique_ptr<folly::IOBuf>>(ciphertext),
        associatedData,
        seqNum);
    if (!plaintext) {
      throw std::runtime_error("decryption failed");
    }
    return std::move(*plaintext);
  }

  /**
   * Decrypt ciphertext. Will return none if the ciphertext does not decrypt
   * successfully. May still throw from errors unrelated to ciphertext.
   */
  virtual folly::Optional<std::unique_ptr<folly::IOBuf>> tryDecrypt(
      std::unique_ptr<folly::IOBuf>&& ciphertext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const = 0;

  /**
   * Returns the number of bytes the aead will add to the plaintext (size of
   * ciphertext - size of plaintext).
   */
  virtual size_t getCipherOverhead() const = 0;
};
} // namespace fizz
