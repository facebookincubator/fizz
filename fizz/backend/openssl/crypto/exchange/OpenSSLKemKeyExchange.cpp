/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/backend/openssl/crypto/exchange/OpenSSLKemKeyExchange.h>

#if OPENSSL_VERSION_NUMBER >= 0x30500000L

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

namespace fizz {
namespace openssl {

namespace {

folly::ssl::EvpPkeyCtxUniquePtr makeNamedCtx(const std::string& groupName) {
  return folly::ssl::EvpPkeyCtxUniquePtr(
      EVP_PKEY_CTX_new_from_name(nullptr, groupName.c_str(), nullptr));
}

// Builds an EVP_PKEY holding just the peer's encoded public key for the named
// hybrid group, so the server can encapsulate to it.
Status importPublicKey(
    folly::ssl::EvpPkeyUniquePtr& ret,
    Error& err,
    const std::string& groupName,
    folly::ByteRange pub) {
  auto ctx = makeNamedCtx(groupName);
  if (!ctx) {
    return err.error("kem: failed to create import ctx");
  }
  if (EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
    return err.error("kem: fromdata_init failed");
  }
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(
          OSSL_PKEY_PARAM_PUB_KEY,
          const_cast<unsigned char*>(pub.data()),
          pub.size()),
      OSSL_PARAM_construct_end()};
  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0 ||
      pkey == nullptr) {
    return err.error("kem: fromdata failed to import public key");
  }
  ret.reset(pkey);
  return Status::Success;
}

// Measures the encoded public-key and ciphertext lengths for a named hybrid
// group by generating a throwaway keypair and querying encapsulate. Returns
// false if the group is unavailable.
bool measureSizes(const std::string& groupName, size_t& pubLen, size_t& ctLen) {
  pubLen = 0;
  ctLen = 0;
  auto kgCtx = makeNamedCtx(groupName);
  if (!kgCtx || EVP_PKEY_keygen_init(kgCtx.get()) <= 0) {
    return false;
  }
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_generate(kgCtx.get(), &raw) <= 0 || raw == nullptr) {
    return false;
  }
  folly::ssl::EvpPkeyUniquePtr key(raw);
  unsigned char* pub = nullptr;
  pubLen = EVP_PKEY_get1_encoded_public_key(key.get(), &pub);
  if (pub != nullptr) {
    OPENSSL_free(pub);
  }
  folly::ssl::EvpPkeyCtxUniquePtr ctx(
      EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr));
  size_t secretLen = 0;
  if (ctx && EVP_PKEY_encapsulate_init(ctx.get(), nullptr) > 0) {
    EVP_PKEY_encapsulate(ctx.get(), nullptr, &ctLen, nullptr, &secretLen);
  }
  return pubLen != 0 && ctLen != 0;
}

} // namespace

bool isKemGroupAvailable(const char* groupName) {
  folly::ssl::EvpPkeyCtxUniquePtr ctx(
      EVP_PKEY_CTX_new_from_name(nullptr, groupName, nullptr));
  return ctx != nullptr;
}

Status OpenSSLKemKeyExchange::createKeyExchange(
    std::unique_ptr<KeyExchange>& ret,
    Error& err,
    KeyExchangeRole role,
    std::string groupName) {
  if (!isKemGroupAvailable(groupName.c_str())) {
    return err.error("kem: group not available in OpenSSL providers");
  }
  if (role == KeyExchangeRole::Server) {
    ret = std::make_unique<OpenSSLKemServerKeyExchange>(std::move(groupName));
  } else {
    ret = std::make_unique<OpenSSLKemClientKeyExchange>(std::move(groupName));
  }
  return Status::Success;
}

/* Client */

Status OpenSSLKemClientKeyExchange::generateKeyPair(Error& err) {
  auto ctx = makeNamedCtx(groupName_);
  if (!ctx) {
    return err.error("kem: failed to create keygen ctx");
  }
  if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
    return err.error("kem: keygen_init failed");
  }
  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_generate(ctx.get(), &pkey) <= 0 || pkey == nullptr) {
    return err.error("kem: keypair generation failed");
  }
  key_.reset(pkey);
  return Status::Success;
}

Status OpenSSLKemClientKeyExchange::getKeyShare(
    std::unique_ptr<folly::IOBuf>& ret,
    Error& err) const {
  if (!key_) {
    return err.error("kem: key not generated");
  }
  unsigned char* pub = nullptr;
  size_t pubLen = EVP_PKEY_get1_encoded_public_key(key_.get(), &pub);
  if (pubLen == 0 || pub == nullptr) {
    return err.error("kem: failed to encode public key");
  }
  ret = folly::IOBuf::copyBuffer(pub, pubLen);
  OPENSSL_free(pub);
  return Status::Success;
}

Status OpenSSLKemClientKeyExchange::generateSharedSecret(
    std::unique_ptr<folly::IOBuf>& ret,
    Error& err,
    folly::ByteRange keyShare) const {
  if (!key_) {
    return err.error("kem: key not generated");
  }
  folly::ssl::EvpPkeyCtxUniquePtr ctx(
      EVP_PKEY_CTX_new_from_pkey(nullptr, key_.get(), nullptr));
  if (!ctx || EVP_PKEY_decapsulate_init(ctx.get(), nullptr) <= 0) {
    return err.error("kem: decapsulate_init failed");
  }
  size_t secretLen = 0;
  if (EVP_PKEY_decapsulate(
          ctx.get(),
          nullptr,
          &secretLen,
          keyShare.data(),
          keyShare.size()) <= 0) {
    return err.error("kem: decapsulate size query failed");
  }
  auto secret = folly::IOBuf::create(secretLen);
  if (EVP_PKEY_decapsulate(
          ctx.get(),
          secret->writableData(),
          &secretLen,
          keyShare.data(),
          keyShare.size()) <= 0) {
    return err.error("kem: decapsulate failed");
  }
  secret->append(secretLen);
  ret = std::move(secret);
  return Status::Success;
}

Status OpenSSLKemClientKeyExchange::clone(
    std::unique_ptr<KeyExchange>& ret,
    Error& err) const {
  if (!key_) {
    return err.error("kem: key not generated");
  }
  // Share ownership of the underlying key; up_ref is version-independent
  // whereas EVP_PKEY_dup historically returned NULL for ML-KEM keys.
  if (EVP_PKEY_up_ref(key_.get()) <= 0) {
    return err.error("kem: up_ref failed");
  }
  auto copy = std::make_unique<OpenSSLKemClientKeyExchange>(groupName_);
  copy->key_.reset(key_.get());
  ret = std::move(copy);
  return Status::Success;
}

std::size_t OpenSSLKemClientKeyExchange::getExpectedKeyShareSize() const {
  // The client receives the server's ciphertext. Sizes are fixed per group,
  // so cache after the first query to avoid a keygen on every call.
  if (expectedShareSize_ == 0) {
    size_t pubLen = 0;
    size_t ctLen = 0;
    measureSizes(groupName_, pubLen, ctLen);
    expectedShareSize_ = ctLen;
  }
  return expectedShareSize_;
}

/* Server */

Status OpenSSLKemServerKeyExchange::getKeyShare(
    std::unique_ptr<folly::IOBuf>& ret,
    Error& err) const {
  if (!cipherText_) {
    return err.error("kem: ciphertext not generated");
  }
  ret = cipherText_->clone();
  return Status::Success;
}

Status OpenSSLKemServerKeyExchange::generateSharedSecret(
    std::unique_ptr<folly::IOBuf>& ret,
    Error& err,
    folly::ByteRange keyShare) const {
  folly::ssl::EvpPkeyUniquePtr peerKey;
  FIZZ_RETURN_ON_ERROR(importPublicKey(peerKey, err, groupName_, keyShare));
  folly::ssl::EvpPkeyCtxUniquePtr ctx(
      EVP_PKEY_CTX_new_from_pkey(nullptr, peerKey.get(), nullptr));
  if (!ctx || EVP_PKEY_encapsulate_init(ctx.get(), nullptr) <= 0) {
    return err.error("kem: encapsulate_init failed");
  }
  size_t ctLen = 0;
  size_t secretLen = 0;
  if (EVP_PKEY_encapsulate(ctx.get(), nullptr, &ctLen, nullptr, &secretLen) <=
      0) {
    return err.error("kem: encapsulate size query failed");
  }
  auto cipherText = folly::IOBuf::create(ctLen);
  auto secret = folly::IOBuf::create(secretLen);
  if (EVP_PKEY_encapsulate(
          ctx.get(),
          cipherText->writableData(),
          &ctLen,
          secret->writableData(),
          &secretLen) <= 0) {
    return err.error("kem: encapsulate failed");
  }
  cipherText->append(ctLen);
  secret->append(secretLen);
  cipherText_ = std::move(cipherText);
  ret = std::move(secret);
  return Status::Success;
}

Status OpenSSLKemServerKeyExchange::clone(
    std::unique_ptr<KeyExchange>& ret,
    Error& err) const {
  if (!cipherText_) {
    return err.error("kem: ciphertext not generated");
  }
  auto copy = std::make_unique<OpenSSLKemServerKeyExchange>(groupName_);
  copy->cipherText_ = cipherText_->clone();
  copy->cipherText_->coalesce();
  ret = std::move(copy);
  return Status::Success;
}

std::size_t OpenSSLKemServerKeyExchange::getExpectedKeyShareSize() const {
  // The server receives the client's encoded public key. Cache it.
  if (expectedShareSize_ == 0) {
    size_t pubLen = 0;
    size_t ctLen = 0;
    measureSizes(groupName_, pubLen, ctLen);
    expectedShareSize_ = pubLen;
  }
  return expectedShareSize_;
}

} // namespace openssl
} // namespace fizz

#endif // OPENSSL_VERSION_NUMBER >= 0x30500000L
