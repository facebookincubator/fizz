/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/fizz-config.h>

#include <openssl/opensslv.h>

// Native ML-KEM (FIPS 203) hybrid groups (e.g. X25519MLKEM768) are only
// available in the stock OpenSSL providers starting with 3.5. Everything in
// this file is compiled out on older OpenSSL so non-3.5 builds are unaffected.
#if OPENSSL_VERSION_NUMBER >= 0x30500000L

#include <fizz/crypto/exchange/KeyExchange.h>
#include <folly/ssl/OpenSSLPtrTypes.h>

#include <string>

namespace fizz {
namespace openssl {

/**
 * Returns true if the running OpenSSL providers expose the given hybrid KEM
 * key management (e.g. "X25519MLKEM768"). Used by the factory to decide whether
 * the native path can be taken before falling back to liboqs.
 */
bool isKemGroupAvailable(const char* groupName);

/**
 * KEM-based key exchange backed by OpenSSL 3.5's native hybrid groups
 * (X25519MLKEM768 et al). OpenSSL performs the X25519 + ML-KEM combine
 * internally, so fizz only drives the public encapsulate/decapsulate APIs.
 *
 * Because KEMs are asymmetric (client keygen + decapsulate, server
 * encapsulate), the role is split into two concrete subclasses, mirroring the
 * liboqs backend. Use createKeyExchange() to obtain the right one.
 */
class OpenSSLKemKeyExchange : public KeyExchange {
 public:
  static Status createKeyExchange(
      std::unique_ptr<KeyExchange>& ret,
      Error& err,
      KeyExchangeRole role,
      std::string groupName);

  ~OpenSSLKemKeyExchange() override = default;

 protected:
  explicit OpenSSLKemKeyExchange(std::string groupName)
      : groupName_(std::move(groupName)) {}

  std::string groupName_;
};

/**
 * Client side: generates the keypair, shares the public key, and decapsulates
 * the server's ciphertext into the shared secret.
 */
class OpenSSLKemClientKeyExchange : public OpenSSLKemKeyExchange {
 public:
  explicit OpenSSLKemClientKeyExchange(std::string groupName)
      : OpenSSLKemKeyExchange(std::move(groupName)) {}

  ~OpenSSLKemClientKeyExchange() override = default;

  Status generateKeyPair(Error& err) override;
  Status getKeyShare(std::unique_ptr<folly::IOBuf>& ret, Error& err)
      const override;
  Status generateSharedSecret(
      std::unique_ptr<folly::IOBuf>& ret,
      Error& err,
      folly::ByteRange keyShare) const override;
  Status clone(std::unique_ptr<KeyExchange>& ret, Error& err) const override;
  std::size_t getExpectedKeyShareSize() const override;

 private:
  folly::ssl::EvpPkeyUniquePtr key_;
  mutable std::size_t expectedShareSize_{0};
};

/**
 * Server side: imports the client's public key, encapsulates to produce a
 * ciphertext (its key share) and the shared secret. No keypair of its own.
 */
class OpenSSLKemServerKeyExchange : public OpenSSLKemKeyExchange {
 public:
  explicit OpenSSLKemServerKeyExchange(std::string groupName)
      : OpenSSLKemKeyExchange(std::move(groupName)) {}

  ~OpenSSLKemServerKeyExchange() override = default;

  Status generateKeyPair(Error& /*err*/) override {
    return Status::Success;
  }
  Status getKeyShare(std::unique_ptr<folly::IOBuf>& ret, Error& err)
      const override;
  Status generateSharedSecret(
      std::unique_ptr<folly::IOBuf>& ret,
      Error& err,
      folly::ByteRange keyShare) const override;
  Status clone(std::unique_ptr<KeyExchange>& ret, Error& err) const override;
  std::size_t getExpectedKeyShareSize() const override;

 private:
  mutable std::unique_ptr<folly::IOBuf> cipherText_;
  mutable std::size_t expectedShareSize_{0};
};

} // namespace openssl
} // namespace fizz

#endif // OPENSSL_VERSION_NUMBER >= 0x30500000L
