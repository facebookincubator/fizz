/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/crypto/HpkeUtils.h>

namespace fizz {
namespace hpke {

HpkeSuiteId generateHpkeSuiteId(NamedGroup group, HashFunction hash, CipherSuite suite) {
  std::unique_ptr<folly::IOBuf> suiteId = folly::IOBuf::copyBuffer("HPKE");
  folly::io::Appender appender(suiteId.get(), 6);
  detail::write(getKEMId(group), appender);
  detail::write(getKDFId(hash), appender);
  detail::write(getAeadId(suite), appender);

  return suiteId;
}

KEMId getKEMId(NamedGroup group) {
  switch (group) {
    case NamedGroup::secp256r1:
      return KEMId::secp256r1;
    case NamedGroup::secp384r1:
      return KEMId::secp384r1;
    case NamedGroup::secp521r1:
      return KEMId::secp521r1;
    case NamedGroup::x25519:
      return KEMId::x25519;
    default:
      throw std::runtime_error("ke: not implemented");
  }
}

KDFId getKDFId(HashFunction hash) {
  switch (hash) {
    case HashFunction::Sha256:
      return KDFId::Sha256;
    case HashFunction::Sha384:
      return KDFId::Sha384;
    default:
      throw std::runtime_error("kdf: not implemented");
  }
}

AeadId getAeadId(CipherSuite suite) {
  switch (suite) {
    case CipherSuite::TLS_AES_128_GCM_SHA256:
      return AeadId::TLS_AES_128_GCM_SHA256;
    case CipherSuite::TLS_AES_256_GCM_SHA384:
      return AeadId::TLS_AES_256_GCM_SHA384;
    case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
      return AeadId::TLS_CHACHA20_POLY1305_SHA256;
    default:
      throw std::runtime_error("ciphersuite: not implemented");
  }
}

} // namespace hpke
} // namespace fizz
