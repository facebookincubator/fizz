/*
 *  Copyright (c) Meta Platforms, Inc. and affiliates.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/backend/openssl/crypto/exchange/X25519.h>

#include <openssl/err.h>
#include <openssl/evp.h>

namespace fizz::openssl {

Status X25519KeyExchange::setPrivateKey(
    Error& err,
    std::unique_ptr<folly::IOBuf> gotPrivKey) {
  if (!gotPrivKey || gotPrivKey->computeChainDataLength() != kKeySize) {
    return err.error("Invalid Private Key.");
  }
  auto privKey = gotPrivKey->coalesce();
  folly::ssl::EvpPkeyUniquePtr key(EVP_PKEY_new_raw_private_key(
      EVP_PKEY_X25519, nullptr, privKey.data(), privKey.size()));
  if (!key) {
    ERR_clear_error();
    return err.error("Invalid Private Key.");
  }
  key_ = std::move(key);
  return Status::Success;
}

Status X25519KeyExchange::generateKeyPair(Error& err) {
  folly::ssl::EvpPkeyCtxUniquePtr ctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
  if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1) {
    return err.error("Could not initialize X25519 key generation");
  }
  EVP_PKEY* key = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &key) != 1 || !key) {
    return err.error("Could not generate X25519 keys");
  }
  key_.reset(key);
  return Status::Success;
}

Status X25519KeyExchange::getKeyShare(
    std::unique_ptr<folly::IOBuf>& ret,
    Error& err) const {
  if (!key_) {
    return err.error("Key not generated");
  }
  auto keyShare = folly::IOBuf::create(kKeySize);
  size_t length = kKeySize;
  if (EVP_PKEY_get_raw_public_key(
          key_.get(), keyShare->writableData(), &length) != 1 ||
      length != kKeySize) {
    return err.error("Could not get X25519 public key");
  }
  keyShare->append(length);
  ret = std::move(keyShare);
  return Status::Success;
}

Status X25519KeyExchange::generateSharedSecret(
    std::unique_ptr<folly::IOBuf>& ret,
    Error& err,
    folly::ByteRange keyShare) const {
  if (!key_) {
    return err.error("Key not generated");
  }
  if (keyShare.size() != kKeySize) {
    return err.error("Invalid external public key");
  }
  folly::ssl::EvpPkeyUniquePtr peerKey(EVP_PKEY_new_raw_public_key(
      EVP_PKEY_X25519, nullptr, keyShare.data(), keyShare.size()));
  if (!peerKey) {
    ERR_clear_error();
    return err.error("Invalid external public key");
  }
  folly::ssl::EvpPkeyCtxUniquePtr ctx(EVP_PKEY_CTX_new(key_.get(), nullptr));
  if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1 ||
      EVP_PKEY_derive_set_peer(ctx.get(), peerKey.get()) != 1) {
    return err.error("Could not initialize X25519 key derivation");
  }
  auto secret = folly::IOBuf::create(kKeySize);
  size_t length = kKeySize;
  // Fails for a small-order point, whose shared secret is all zeros.
  if (EVP_PKEY_derive(ctx.get(), secret->writableData(), &length) != 1 ||
      length != kKeySize) {
    ERR_clear_error();
    return err.error("Invalid point");
  }
  secret->append(length);
  ret = std::move(secret);
  return Status::Success;
}

Status X25519KeyExchange::clone(std::unique_ptr<KeyExchange>& ret, Error& err)
    const {
  if (!key_) {
    return err.error("Key not generated");
  }
  auto kexCopy = std::make_unique<X25519KeyExchange>();
  EVP_PKEY_up_ref(key_.get());
  kexCopy->key_.reset(key_.get());
  ret = std::move(kexCopy);
  return Status::Success;
}

std::size_t X25519KeyExchange::getExpectedKeyShareSize() const {
  return kKeySize;
}

} // namespace fizz::openssl
