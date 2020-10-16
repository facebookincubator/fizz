/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <fizz/crypto/test/TestUtil.h>

#include <fizz/crypto/hpke/Hpke.h>
#include <fizz/crypto/hpke/Utils.h>
#include <fizz/extensions/ech/Encryption.h>
#include <fizz/extensions/ech/test/TestUtil.h>
#include <fizz/protocol/test/TestMessages.h>

using namespace fizz::test;

namespace fizz {
namespace extensions {
namespace test {

static constexpr folly::StringPiece expectedClientHelloInner{
    "03034444444444444444444444444444444444444444444444444444444444444444000004130113020100006a002b0003020304000a00060004001d00170033000e000c001d00086b65797368617265000d00060004040308040000001500130000107777772e686f73746e616d652e636f6d001000050003026832002d0003020100ff030010972a9c468ef0891fd22c052c6785f6a6"};
static constexpr folly::StringPiece expectedRecordDigest{
    "fb651f6d036df7b3f54d96e1e5bcc1c7db78056dff861ea4e798d03e65a2ca1e"};

class MockOpenSSLECKeyExchange256 : public OpenSSLECKeyExchange<P256> {
 public:
  MOCK_METHOD0(generateKeyPair, void());
};

hpke::HpkeContext getContext(std::unique_ptr<folly::IOBuf> enc) {
  auto kex = std::make_unique<MockOpenSSLECKeyExchange256>();
  kex->setPrivateKey(getPrivateKey(kP256Key));
  auto suiteId = hpke::generateHpkeSuiteId(
      NamedGroup::secp256r1,
      HashFunction::Sha256,
      CipherSuite::TLS_AES_128_GCM_SHA256);

  hpke::SetupParam setupParam{
      std::make_unique<DHKEM>(
          std::move(kex),
          NamedGroup::secp256r1,
          std::make_unique<fizz::hpke::Hkdf>(
              folly::IOBuf::copyBuffer("HPKE-05 "),
              std::make_unique<HkdfImpl>(HkdfImpl::create<Sha256>()))),
      makeCipher(hpke::AeadId::TLS_AES_128_GCM_SHA256),
      std::make_unique<fizz::hpke::Hkdf>(
          folly::IOBuf::copyBuffer("HPKE-05 "),
          std::make_unique<HkdfImpl>(HkdfImpl::create<Sha256>())),
      std::move(suiteId),
  };
  return setupWithDecap(
      hpke::Mode::Base,
      enc->coalesce(),
      folly::IOBuf::copyBuffer("tls13-ech"),
      folly::none,
      std::move(setupParam));
}

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

TEST(EncryptionTest, TestValidEncryptClientHello) {
  auto testCipherSuite = HpkeCipherSuite{hpke::KDFId::Sha256,
                                         hpke::AeadId::TLS_AES_128_GCM_SHA256};
  auto getTestConfig = [testCipherSuite]() {
    auto testConfig = getECHConfigContent();
    testConfig.cipher_suites = {testCipherSuite};
    auto publicKey = detail::encodeECPublicKey(getPublicKey(kP256PublicKey));
    testConfig.kem_id = hpke::KEMId::secp256r1;
    testConfig.public_key = std::move(publicKey);
    return testConfig;
  };

  SupportedECHConfig supportedConfig{getTestConfig(), testCipherSuite};

  auto kex = std::make_unique<MockOpenSSLECKeyExchange256>();
  auto privateKey = getPrivateKey(kP256Key);
  kex->setPrivateKey(std::move(privateKey));
  EXPECT_CALL(*kex, generateKeyPair()).Times(1);

  auto gotECH = encryptClientHello(
      std::move(kex), std::move(supportedConfig), TestMessages::clientHello());
  EXPECT_EQ(gotECH.suite.kdfId, testCipherSuite.kdfId);
  EXPECT_EQ(gotECH.suite.aeadId, testCipherSuite.aeadId);

  auto context = getContext(std::move(gotECH.enc));
  std::unique_ptr<folly::IOBuf> gotClientHelloInner = context.open(
      folly::IOBuf::copyBuffer("").get(), std::move(gotECH.encrypted_ch));

  EXPECT_TRUE(folly::IOBufEqualTo()(
      gotClientHelloInner, toIOBuf(expectedClientHelloInner)));

  EXPECT_TRUE(folly::IOBufEqualTo()(
      gotECH.record_digest, toIOBuf(expectedRecordDigest)));
}

} // namespace test
} // namespace extensions
} // namespace fizz
