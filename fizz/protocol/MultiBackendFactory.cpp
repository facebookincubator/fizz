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
#if FIZZ_HAVE_SODIUM
#include <fizz/backend/libsodium/LibSodium.h>
#endif
#include <fizz/backend/openssl/OpenSSL.h>
#include <fizz/backend/openssl/certificate/CertUtils.h>
#include <fizz/crypto/Random.h>
#include <fizz/crypto/exchange/HybridKeyExchange.h>

namespace fizz {

namespace {
#if FIZZ_HAVE_SODIUM
using X25519KeyExchangeImpl = libsodium::X25519KeyExchange;
#else
using X25519KeyExchangeImpl = openssl::X25519KeyExchange;
#endif
} // namespace

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
      ret = std::make_unique<X25519KeyExchangeImpl>();
      return Status::Success;
#if FIZZ_HAVE_OQS
    case NamedGroup::X25519MLKEM768: {
      std::unique_ptr<KeyExchange> oqsKex;
      FIZZ_RETURN_ON_ERROR(
          fizz::liboqs::makeKeyExchange<MLKEM768>(oqsKex, err, role));
      std::unique_ptr<HybridKeyExchange> hybridKex;
      FIZZ_RETURN_ON_ERROR(
          HybridKeyExchange::create(
              hybridKex,
              err,
              std::move(oqsKex),
              std::make_unique<X25519KeyExchangeImpl>()));
      ret = std::move(hybridKex);
      return Status::Success;
    }
    case NamedGroup::MLKEM512X25519:
    case NamedGroup::X25519MLKEM512_FB: {
      std::unique_ptr<KeyExchange> oqsKex;
      FIZZ_RETURN_ON_ERROR(
          fizz::liboqs::makeKeyExchange<MLKEM512>(oqsKex, err, role));
      std::unique_ptr<HybridKeyExchange> hybridKex;
      FIZZ_RETURN_ON_ERROR(
          HybridKeyExchange::create(
              hybridKex,
              err,
              std::move(oqsKex),
              std::make_unique<X25519KeyExchangeImpl>()));
      ret = std::move(hybridKex);
      return Status::Success;
    }
#endif
    default:
      return err.error("ke: not implemented");
  }
}

Status MultiBackendFactory::makeAead(
    std::unique_ptr<Aead>& ret,
    Error& err,
    CipherSuite cipher) const {
  switch (cipher) {
    case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
      FIZZ_RETURN_ON_ERROR(
          openssl::OpenSSLEVPCipher::makeCipher<fizz::ChaCha20Poly1305>(
              ret, err));
      return Status::Success;
    case CipherSuite::TLS_AES_128_GCM_SHA256:
      FIZZ_RETURN_ON_ERROR(
          openssl::OpenSSLEVPCipher::makeCipher<fizz::AESGCM128>(ret, err));
      return Status::Success;
    case CipherSuite::TLS_AES_256_GCM_SHA384:
      FIZZ_RETURN_ON_ERROR(
          openssl::OpenSSLEVPCipher::makeCipher<fizz::AESGCM256>(ret, err));
      return Status::Success;
#if FIZZ_HAVE_LIBAEGIS
    case CipherSuite::TLS_AEGIS_256_SHA512:
      return libaegis::makeCipher<fizz::AEGIS256>(ret, err);
    case CipherSuite::TLS_AEGIS_128L_SHA256:
      return libaegis::makeCipher<fizz::AEGIS128L>(ret, err);
    case CipherSuite::TLS_AEGIS_128X2_SHA256:
      return libaegis::makeCipher<fizz::AEGIS128X2>(ret, err);
    case CipherSuite::TLS_AEGIS_128X4_SHA256:
      return libaegis::makeCipher<fizz::AEGIS128X4>(ret, err);
#endif
    default:
      return err.error("aead: not implemented");
  }
}

Status MultiBackendFactory::makeHasherFactory(
    const HasherFactoryWithMetadata*& ret,
    Error& err,
    HashFunction digest) const {
  switch (digest) {
    case HashFunction::Sha256:
      ret = openssl::hasherFactory<fizz::Sha256>();
      return Status::Success;
    case HashFunction::Sha384:
      ret = openssl::hasherFactory<fizz::Sha384>();
      return Status::Success;
    case HashFunction::Sha512:
      ret = openssl::hasherFactory<fizz::Sha512>();
      return Status::Success;
    default:
      return err.error("makeHasher: not implemented");
  }
}

Status MultiBackendFactory::makeX25519KeyExchange(
    std::unique_ptr<KeyExchange>& ret,
    Error& err,
    std::unique_ptr<folly::IOBuf> privateKey) {
  auto kex = std::make_unique<X25519KeyExchangeImpl>();
  FIZZ_RETURN_ON_ERROR(kex->setPrivateKey(err, std::move(privateKey)));
  ret = std::move(kex);
  return Status::Success;
}

Status MultiBackendFactory::makeRandomBytes(
    Error& err,
    unsigned char* out,
    size_t count) const {
  return fizz::random(err, out, count);
}

Status MultiBackendFactory::makePeerCert(
    std::unique_ptr<PeerCert>& ret,
    Error& err,
    CertificateEntry certEntry,
    bool /*leaf*/) const {
  if (certEntry.cert_data->empty()) {
    return err.error("empty peer cert");
  }
  FIZZ_RETURN_ON_ERROR(
      openssl::CertUtils::makePeerCert(
          ret, err, std::move(certEntry.cert_data)));
  return Status::Success;
}

} // namespace fizz
