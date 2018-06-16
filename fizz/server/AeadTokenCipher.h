/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/record/Types.h>
#include <folly/Optional.h>
#include <folly/io/IOBuf.h>

namespace fizz {
namespace server {

/**
 * Used to encrypt and decrypt various tokens (for example PSKs).
 */
template <typename AeadType, typename HkdfType>
class AeadTokenCipher {
 public:
  static constexpr size_t kMinTokenSecretLength = 32;

  /**
   * Set additional context strings for use with these tokens. The strings will
   * be used, in order, as part of the key derivation so that different contexts
   * will result in different keys, preventing keys from one context from being
   * used for another.
   */
  explicit AeadTokenCipher(std::vector<std::string> contextStrings)
      : contextStrings_(std::move(contextStrings)) {}

  ~AeadTokenCipher() {
    clearSecrets();
  }

  /**
   * Set secrets to use for token encryption/decryption.
   * The first one will be used for encryption.
   * All secrets must be at least kMinTokenSecretLength long.
   */
  bool setSecrets(const std::vector<folly::ByteRange>& tokenSecrets);

  folly::Optional<Buf> encrypt(Buf plaintext) const;

  folly::Optional<Buf> decrypt(Buf) const;

 private:
  using Secret = std::vector<uint8_t>;
  static constexpr size_t kSaltLength = HkdfType::HashLen;
  using Salt = std::array<uint8_t, kSaltLength>;
  using SeqNum = uint32_t;
  static constexpr size_t kTokenHeaderLength = kSaltLength + sizeof(SeqNum);

  AeadType createAead(folly::ByteRange secret, folly::ByteRange salt) const;

  void clearSecrets();

  // First secret is the one used to encrypt.
  std::vector<Secret> secrets_;

  std::vector<std::string> contextStrings_;
};
} // namespace server
} // namespace fizz

#include <fizz/server/AeadTokenCipher-inl.h>
