/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/crypto/openssl/OpenSSLKeyUtils.h>
#include <folly/io/IOBuf.h>

namespace fizz {

namespace detail {

std::unique_ptr<folly::IOBuf> ecSign(
    folly::ByteRange data,
    const folly::ssl::EvpPkeyUniquePtr& pkey,
    int hashNid);

void ecVerify(
    folly::ByteRange data,
    folly::ByteRange signature,
    const folly::ssl::EvpPkeyUniquePtr& pkey,
    int hashNid);

std::unique_ptr<folly::IOBuf> rsaPssSign(
    folly::ByteRange data,
    const folly::ssl::EvpPkeyUniquePtr& pkey,
    int hashNid);

void rsaPssVerify(
    folly::ByteRange data,
    folly::ByteRange signature,
    const folly::ssl::EvpPkeyUniquePtr& pkey,
    int hashNid);
} // namespace detail

template <>
template <>
inline std::unique_ptr<folly::IOBuf>
OpenSSLSignature<KeyType::P256>::sign<SignatureScheme::ecdsa_secp256r1_sha256>(
    folly::ByteRange data) const {
  return detail::ecSign(data, pkey_, NID_sha256);
}

template <>
template <>
inline void OpenSSLSignature<KeyType::P256>::verify<
    SignatureScheme::ecdsa_secp256r1_sha256>(
    folly::ByteRange data,
    folly::ByteRange signature) const {
  return detail::ecVerify(data, signature, pkey_, NID_sha256);
}

template <>
inline void OpenSSLSignature<KeyType::P256>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  detail::validateECKey(pkey, NID_X9_62_prime256v1);
  pkey_ = std::move(pkey);
}

template <SignatureScheme Scheme>
struct RsaPssSigAlg {};

template <>
struct RsaPssSigAlg<SignatureScheme::rsa_pss_sha256> {
  static constexpr int HashNid = NID_sha256;
};

template <>
template <SignatureScheme Scheme>
std::unique_ptr<folly::IOBuf> OpenSSLSignature<KeyType::RSA>::sign(
    folly::ByteRange data) const {
  return detail::rsaPssSign(data, pkey_, RsaPssSigAlg<Scheme>::HashNid);
}

template <>
template <SignatureScheme Scheme>
void OpenSSLSignature<KeyType::RSA>::verify(
    folly::ByteRange data,
    folly::ByteRange signature) const {
  return detail::rsaPssVerify(
      data, signature, pkey_, RsaPssSigAlg<Scheme>::HashNid);
}

template <>
inline void OpenSSLSignature<KeyType::RSA>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  if (EVP_PKEY_id(pkey.get()) != EVP_PKEY_RSA) {
    throw std::runtime_error("key not rsa");
  }
  pkey_ = std::move(pkey);
}
} // namespace fizz
