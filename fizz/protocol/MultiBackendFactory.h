/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/protocol/Factory.h>

namespace fizz {
/**
 * A fizz::Factory implementation composed of primitives from
 * multiple backends.
 */
class MultiBackendFactory : public Factory {
 public:
  Status makeKeyExchange(
      std::unique_ptr<KeyExchange>& ret,
      Error& err,
      NamedGroup group,
      KeyExchangeRole role) const override;

  Status makeAead(std::unique_ptr<Aead>& ret, Error& err, CipherSuite cipher)
      const override;

  Status makeHasherFactory(
      const HasherFactoryWithMetadata*& ret,
      Error& err,
      HashFunction digest) const override;

  Status makePeerCert(
      std::unique_ptr<PeerCert>& ret,
      Error& err,
      CertificateEntry certEntry,
      bool leaf) const override;

  Status makeRandomBytes(Error& err, unsigned char* out, size_t count)
      const override;

  // TODO: Move this out of MultiBackendFactory once Fizz has a home for the
  // default crypto implementations, such as fizz/crypto/DefaultCrypto.h.
  /**
   * Creates the X25519 key exchange that makeKeyExchange() uses, with the given
   * private key.
   */
  static Status makeX25519KeyExchange(
      std::unique_ptr<KeyExchange>& ret,
      Error& err,
      std::unique_ptr<folly::IOBuf> privateKey);
};
} // namespace fizz
