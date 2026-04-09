/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/fizz-config.h>

#include <fizz/protocol/MultiBackendFactory.h>

#include <fizz/backend/libaegis/LibAEGIS.h>
#include <fizz/backend/liboqs/LibOQS.h>
#include <fizz/backend/libsodium/LibSodium.h>
#include <fizz/backend/openssl/OpenSSL.h>
#include <fizz/backend/openssl/certificate/CertUtils.h>
#include <fizz/crypto/exchange/HybridKeyExchange.h>

namespace fizz {

Status MultiBackendFactory::makeKeyExchange(
    std::unique_ptr<KeyExchange>& ret,
    Error& err,
    NamedGroup group,
    KeyExchangeRole role) const {
  (void)role;
  switch (group) {
    case NamedGroup::secp256r1:
      ret = fizz::openssl::makeKeyExchange<fizz::P256>();
      return Status::Success;
    case NamedGroup::secp384r1:
      ret = fizz::openssl::makeKeyExchange<fizz::P384>();
      return Status::Success;
    case NamedGroup::secp521r1:
      ret = fizz::openssl::makeKeyExchange<fizz::P521>();
      return Status::Success;
    case NamedGroup::x25519:
      ret = fizz::libsodium::makeKeyExchange<fizz::X25519>();
      return Status::Success;
#if FIZZ_HAVE_OQS
    case NamedGroup::X25519MLKEM768:
      ret = std::make_unique<HybridKeyExchange>(
          fizz::liboqs::makeKeyExchange<MLKEM768>(role),
          fizz::libsodium::makeKeyExchange<fizz::X25519>());
      return Status::Success;
    case NamedGroup::X25519MLKEM512_FB:
      ret = std::make_unique<HybridKeyExchange>(
          fizz::liboqs::makeKeyExchange<MLKEM512>(role),
          fizz::libsodium::makeKeyExchange<fizz::X25519>());
      return Status::Success;
#endif
    default:
      return err.error("ke: not implemented");
  }
}

std::unique_ptr<Aead> MultiBackendFactory::makeAead(CipherSuite cipher) const {
  switch (cipher) {
    case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
      return openssl::OpenSSLEVPCipher::makeCipher<fizz::ChaCha20Poly1305>();
    case CipherSuite::TLS_AES_128_GCM_SHA256:
      return openssl::OpenSSLEVPCipher::makeCipher<fizz::AESGCM128>();
    case CipherSuite::TLS_AES_256_GCM_SHA384:
      return openssl::OpenSSLEVPCipher::makeCipher<fizz::AESGCM256>();
    case CipherSuite::TLS_AES_128_OCB_SHA256_EXPERIMENTAL:
      return openssl::OpenSSLEVPCipher::makeCipher<fizz::AESOCB128>();
#if FIZZ_HAVE_LIBAEGIS
    case CipherSuite::TLS_AEGIS_256_SHA512:
      return libaegis::makeCipher<fizz::AEGIS256>();
    case CipherSuite::TLS_AEGIS_128L_SHA256:
      return libaegis::makeCipher<fizz::AEGIS128L>();
#endif
    default:
      throw std::runtime_error("aead: not implemented");
  }
}

const HasherFactoryWithMetadata* MultiBackendFactory::makeHasherFactory(
    HashFunction digest) const {
  switch (digest) {
    case HashFunction::Sha256:
      return openssl::hasherFactory<fizz::Sha256>();
    case HashFunction::Sha384:
      return openssl::hasherFactory<fizz::Sha384>();
    case HashFunction::Sha512:
      return openssl::hasherFactory<fizz::Sha512>();
    default:
      throw std::runtime_error("makeHasher: not implemented");
  }
}

void MultiBackendFactory::makeRandomBytes(unsigned char* out, size_t count)
    const {
  libsodium::random(out, count);
}

std::unique_ptr<PeerCert> MultiBackendFactory::makePeerCert(
    CertificateEntry certEntry,
    bool /*leaf*/) const {
  return openssl::CertUtils::makePeerCert(std::move(certEntry.cert_data));
}

} // namespace fizz
