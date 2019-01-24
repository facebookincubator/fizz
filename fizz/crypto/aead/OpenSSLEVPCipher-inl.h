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
    EVP_CIPHER_CTX* encryptCtx);
} // namespace detail

template <typename EVPImpl>
OpenSSLEVPCipher<EVPImpl>::OpenSSLEVPCipher() {
  encryptCtx_.reset(EVP_CIPHER_CTX_new());
  if (encryptCtx_ == nullptr) {
    throw std::runtime_error("Unable to allocate an EVP_CIPHER_CTX object");
  }
  decryptCtx_.reset(EVP_CIPHER_CTX_new());
  if (decryptCtx_ == nullptr) {
    throw std::runtime_error("Unable to allocate an EVP_CIPHER_CTX object");
  }
  if (EVP_EncryptInit_ex(
          encryptCtx_.get(), EVPImpl::Cipher(), nullptr, nullptr, nullptr) !=
      1) {
    throw std::runtime_error("Init error");
  }
  if (EVP_CIPHER_CTX_ctrl(
          encryptCtx_.get(),
          EVP_CTRL_GCM_SET_IVLEN,
          EVPImpl::kIVLength,
          nullptr) != 1) {
    throw std::runtime_error("Error setting iv length");
  }
  if (EVP_DecryptInit_ex(
          decryptCtx_.get(), EVPImpl::Cipher(), nullptr, nullptr, nullptr) !=
      1) {
    throw std::runtime_error("Init error");
  }
  if (EVP_CIPHER_CTX_ctrl(
          decryptCtx_.get(),
          EVP_CTRL_GCM_SET_IVLEN,
          EVPImpl::kIVLength,
          nullptr) != 1) {
    throw std::runtime_error("Error setting iv length");
  }

  if (EVPImpl::kRequiresPresetTagLen) {
    if (EVP_CIPHER_CTX_ctrl(
            encryptCtx_.get(),
            EVP_CTRL_GCM_SET_TAG,
            EVPImpl::kTagLength,
            nullptr) != 1) {
      throw std::runtime_error("Error setting enc tag length");
    }

    if (EVP_CIPHER_CTX_ctrl(
            decryptCtx_.get(),
            EVP_CTRL_GCM_SET_TAG,
            EVPImpl::kTagLength,
            nullptr) != 1) {
      throw std::runtime_error("Error setting dec tag length");
    }
  }
}

template <typename EVPImpl>
void OpenSSLEVPCipher<EVPImpl>::setKey(TrafficKey trafficKey) {
  trafficKey.key->coalesce();
  trafficKey.iv->coalesce();
  if (trafficKey.key->length() != EVPImpl::kKeyLength) {
    throw std::runtime_error("Invalid key");
  }
  if (trafficKey.iv->length() != EVPImpl::kIVLength) {
    throw std::runtime_error("Invalid IV");
  }
  trafficKey_ = std::move(trafficKey);
  // Cache the IV key. calling coalesce() is not free.
  trafficIvKey_ = trafficKey_.iv->coalesce();
  if (EVP_EncryptInit_ex(
          encryptCtx_.get(),
          nullptr,
          nullptr,
          trafficKey_.key->data(),
          nullptr) != 1) {
    throw std::runtime_error("Error setting encrypt key");
  }
  if (EVP_DecryptInit_ex(
          decryptCtx_.get(),
          nullptr,
          nullptr,
          trafficKey_.key->data(),
          nullptr) != 1) {
    throw std::runtime_error("Error setting decrypt key");
  }
}

template <typename EVPImpl>
std::unique_ptr<folly::IOBuf> OpenSSLEVPCipher<EVPImpl>::encrypt(
    std::unique_ptr<folly::IOBuf>&& plaintext,
    const folly::IOBuf* associatedData,
    uint64_t seqNum) const {
  auto iv = createIV(seqNum);
  return detail::evpEncrypt(
      std::move(plaintext),
      associatedData,
      iv,
      EVPImpl::kTagLength,
      EVPImpl::kOperatesInBlocks,
      headroom_,
      encryptCtx_.get());
}

template <typename EVPImpl>
folly::Optional<std::unique_ptr<folly::IOBuf>>
OpenSSLEVPCipher<EVPImpl>::tryDecrypt(
    std::unique_ptr<folly::IOBuf>&& ciphertext,
    const folly::IOBuf* associatedData,
    uint64_t seqNum) const {
  auto iv = createIV(seqNum);
  // buffer to copy the tag into when we decrypt
  std::array<uint8_t, EVPImpl::kTagLength> tagData;
  folly::MutableByteRange tagOut{tagData};
  return detail::evpDecrypt(
      std::move(ciphertext),
      associatedData,
      iv,
      tagOut,
      EVPImpl::kOperatesInBlocks,
      decryptCtx_.get());
}

template <typename EVPImpl>
size_t OpenSSLEVPCipher<EVPImpl>::getCipherOverhead() const {
  return EVPImpl::kTagLength;
}

template <typename EVPImpl>
std::array<uint8_t, EVPImpl::kIVLength> OpenSSLEVPCipher<EVPImpl>::createIV(
    uint64_t seqNum) const {
  std::array<uint8_t, EVPImpl::kIVLength> iv;
  uint64_t bigEndianSeqNum = folly::Endian::big(seqNum);
  const size_t prefixLength = EVPImpl::kIVLength - sizeof(uint64_t);
  memset(iv.data(), 0, prefixLength);
  memcpy(iv.data() + prefixLength, &bigEndianSeqNum, 8);
  XOR(trafficIvKey_, folly::range(iv));
  return iv;
}
} // namespace fizz
