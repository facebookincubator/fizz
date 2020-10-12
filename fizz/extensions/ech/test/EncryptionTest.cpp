/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <fizz/extensions/ech/Encryption.h>
#include <fizz/extensions/ech/test/TestUtil.h>

namespace fizz {
namespace extensions {
namespace test {

TEST(EncryptionTest, TestValidECHConfigContent) {

  // Add config that doesn't work and cannot be supported
  ECHConfigContentDraft7 invalidConfig = getECHConfigContent();
  invalidConfig.kem_id = hpke::KEMId::secp521r1;

  // Add config that works and can be supported
  ECHConfigContentDraft7 validConfig = getECHConfigContent();

  std::vector<ECHConfigContentDraft7> configs;
  configs.push_back(std::move(invalidConfig));
  configs.push_back(std::move(validConfig));

  std::vector<hpke::KEMId> supportedKEMs{hpke::KEMId::x25519, hpke::KEMId::secp256r1};
  std::vector<hpke::KDFId> supportedHashFunctions{hpke::KDFId::Sha256, hpke::KDFId::Sha512};
  std::vector<hpke::AeadId> supportedCiphers{hpke::AeadId::TLS_AES_256_GCM_SHA384, hpke::AeadId::TLS_AES_128_GCM_SHA256};

  folly::Optional<SupportedECHConfig> result = selectECHConfig(std::move(configs), supportedKEMs, supportedHashFunctions, supportedCiphers);
  EXPECT_TRUE(result.hasValue());

  ECHConfigContentDraft7 gotConfigContent = std::move(result.value().config);
  EXPECT_TRUE(folly::IOBufEqualTo()(encode(std::move(gotConfigContent)), encode(getECHConfigContent())));
  EXPECT_EQ(result.value().cipherSuite.kdfId, hpke::KDFId::Sha256);
  EXPECT_EQ(result.value().cipherSuite.aeadId, hpke::AeadId::TLS_AES_128_GCM_SHA256);
}

TEST(EncryptionTest, TestInvalidECHConfigContent) {
  ECHConfigContentDraft7 config = getECHConfigContent();

  config.kem_id = hpke::KEMId::secp256r1;
  HpkeCipherSuite suite{hpke::KDFId::Sha512, hpke::AeadId::TLS_AES_128_GCM_SHA256};
  std::vector<HpkeCipherSuite> cipher_suites = {suite};
  config.cipher_suites = cipher_suites;

  std::vector<ECHConfigContentDraft7> configs;
  configs.push_back(std::move(config));

  std::vector<hpke::KEMId> supportedKEMs{hpke::KEMId::x25519, hpke::KEMId::secp256r1};
  std::vector<hpke::KDFId> supportedHashFunctions{hpke::KDFId::Sha256};
  std::vector<hpke::AeadId> supportedCiphers{hpke::AeadId::TLS_AES_128_GCM_SHA256};

  folly::Optional<SupportedECHConfig> result = selectECHConfig(std::move(configs), supportedKEMs, supportedHashFunctions, supportedCiphers);
  EXPECT_FALSE(result.hasValue());
}

} // namespace test
} // namespace extensions
} // namespace fizz
