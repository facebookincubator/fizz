/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

namespace fizz {
namespace detail {

template <class T>
class OpenSSLECKeyExchange {
 public:
  void generateKeyPair() {
    key_ = generateECKeyPair(T::curveNid);
  }

  void setPrivateKey(folly::ssl::EvpPkeyUniquePtr privateKey) {
    validateECKey(privateKey, T::curveNid);
    key_ = std::move(privateKey);
  }

  const folly::ssl::EvpPkeyUniquePtr& getKey() const {
    return key_;
  }

  std::unique_ptr<folly::IOBuf> generateSharedSecret(
      const folly::ssl::EvpPkeyUniquePtr& peerKey) const {
    if (!key_) {
      throw std::runtime_error("Key not generated");
    }
    return generateEvpSharedSecret(key_, peerKey);
  }

 private:
  folly::ssl::EvpPkeyUniquePtr key_;
};

template <class T>
class OpenSSLECKeyDecoder {
 public:
  static folly::ssl::EvpPkeyUniquePtr decode(folly::ByteRange range) {
    return decodeECPublicKey(range, T::curveNid);
  }
};

class OpenSSLECKeyEncoder {
 public:
  static std::unique_ptr<folly::IOBuf> encode(
      const folly::ssl::EvpPkeyUniquePtr& key) {
    return encodeECPublicKey(key);
  }
};
} // namespace detail
} // namespace fizz
