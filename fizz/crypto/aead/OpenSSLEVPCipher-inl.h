/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

namespace fizz {
namespace detail {
folly::Optional<std::unique_ptr<folly::IOBuf>> evpDecrypt(
    std::unique_ptr<folly::IOBuf>&& ciphertext,
    const folly::IOBuf* associatedData,
    folly::ByteRange iv,
    folly::MutableByteRange tag,
    bool useBlockOps,
    EVP_CIPHER_CTX* decryptCtx);

std::unique_ptr<folly::IOBuf> evpEncrypt(
    std::unique_ptr<folly::IOBuf>&& plaintext,
    const folly::IOBuf* associatedData,
    folly::ByteRange iv,
    size_t tagLen,
    bool useBlockOps,
    size_t headroom,
    EVP_CIPHER_CTX* encryptCtx,
    bool forceInplace);
} // namespace detail

template <typename EVPImpl>
std::unique_ptr<OpenSSLEVPCipher> OpenSSLEVPCipher::makeCipher() {
  static_assert(EVPImpl::kIVLength >= sizeof(uint64_t), "iv too small");
  static_assert(EVPImpl::kIVLength < kMaxIVLength, "iv too large");
  static_assert(EVPImpl::kTagLength < kMaxTagLength, "tag too large");
  return std::unique_ptr<OpenSSLEVPCipher>(new OpenSSLEVPCipher(
      EVPImpl::kKeyLength,
      EVPImpl::kIVLength,
      EVPImpl::kTagLength,
      EVPImpl::Cipher(),
      EVPImpl::kOperatesInBlocks,
      EVPImpl::kRequiresPresetTagLen));
}
} // namespace fizz
