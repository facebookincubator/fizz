/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/crypto/aead/OpenSSLEVPCipher.h>

namespace fizz {
namespace detail {

std::unique_ptr<folly::IOBuf> evpEncrypt(
    std::unique_ptr<folly::IOBuf>&& plaintext,
    const folly::IOBuf* associatedData,
    folly::ByteRange iv,
    size_t tagLen,
    EVP_CIPHER_CTX* encryptCtx) {
  auto inputLength = plaintext->computeChainDataLength();

  // Setup output buffer.
  std::unique_ptr<folly::IOBuf> output;
  std::unique_ptr<folly::IOBuf> tag = folly::IOBuf::create(tagLen);
  tag->append(tagLen);

  if (plaintext->isShared()) {
    output = folly::IOBuf::create(inputLength);
    output->append(inputLength);
  } else {
    output = plaintext->clone();
  }

  if (EVP_EncryptInit_ex(encryptCtx, nullptr, nullptr, nullptr, iv.data()) !=
      1) {
    throw std::runtime_error("Encryption error");
  }

  if (associatedData) {
    for (auto current : *associatedData) {
      if (current.size() > std::numeric_limits<int>::max()) {
        throw std::runtime_error("too much associated data");
      }
      int len;
      if (EVP_EncryptUpdate(
              encryptCtx,
              nullptr,
              &len,
              current.data(),
              static_cast<int>(current.size())) != 1) {
        throw std::runtime_error("Encryption error");
      }
    }
  }

  int outLen = 0;
  transformBuffer(
      *plaintext,
      *output,
      [&](uint8_t* cipher, const uint8_t* plain, size_t len) {
        if (len > std::numeric_limits<int>::max()) {
          throw std::runtime_error("Encryption error: too much plain text");
        }
        if (EVP_EncryptUpdate(
                encryptCtx, cipher, &outLen, plain, static_cast<int>(len)) !=
            1) {
          throw std::runtime_error("Encryption error");
        }
      });

  // GCM does not write any data at the end.
  if (EVP_EncryptFinal_ex(
          encryptCtx, output->writableData() + inputLength, &outLen) != 1) {
    throw std::runtime_error("Encryption error");
  }
  if (EVP_CIPHER_CTX_ctrl(
          encryptCtx, EVP_CTRL_GCM_GET_TAG, tagLen, tag->writableData()) != 1) {
    throw std::runtime_error("Encryption error");
  }
  output->prependChain(std::move(tag));
  return output;
}

folly::Optional<std::unique_ptr<folly::IOBuf>> evpDecrypt(
    std::unique_ptr<folly::IOBuf>&& ciphertext,
    const folly::IOBuf* associatedData,
    folly::ByteRange iv,
    size_t tagLen,
    EVP_CIPHER_CTX* decryptCtx) {
  auto inputLength = ciphertext->computeChainDataLength();
  if (inputLength < tagLen) {
    return folly::none;
  }
  inputLength -= tagLen;

  std::unique_ptr<folly::IOBuf> output;
  std::unique_ptr<folly::IOBuf> tag = trimBytes(*ciphertext, tagLen);
  if (ciphertext->isShared()) {
    // If in is shared, then we have to make a copy of it.
    output = folly::IOBuf::create(inputLength);
    output->append(inputLength);
  } else {
    // If in is not shared we can do decryption in-place.
    output = ciphertext->clone();
  }

  if (EVP_DecryptInit_ex(decryptCtx, nullptr, nullptr, nullptr, iv.data()) !=
      1) {
    throw std::runtime_error("Decryption error");
  }

  if (associatedData) {
    for (auto current : *associatedData) {
      if (current.size() > std::numeric_limits<int>::max()) {
        throw std::runtime_error("too much associated data");
      }
      int len;
      if (EVP_DecryptUpdate(
              decryptCtx,
              nullptr,
              &len,
              current.data(),
              static_cast<int>(current.size())) != 1) {
        throw std::runtime_error("Decryption error");
      }
    }
  }

  int outLen = 0;
  transformBuffer(
      *ciphertext,
      *output,
      [&](uint8_t* plain, const uint8_t* cipher, size_t len) {
        if (len > std::numeric_limits<int>::max()) {
          throw std::runtime_error("Decryption error: too much cipher text");
        }
        if (EVP_DecryptUpdate(
                decryptCtx, plain, &outLen, cipher, static_cast<int>(len)) !=
            1) {
          throw std::runtime_error("Decryption error");
        }
      });
  if (EVP_CIPHER_CTX_ctrl(
          decryptCtx, EVP_CTRL_GCM_SET_TAG, tagLen, (void*)tag->data()) != 1) {
    throw std::runtime_error("Decryption error");
  }
  if (EVP_DecryptFinal_ex(
          decryptCtx, output->writableData() + inputLength, &outLen) != 1) {
    return folly::none;
  }
  return std::move(output);
}

} // namespace detail
} // namespace fizz
