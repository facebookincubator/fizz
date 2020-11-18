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
#include <fizz/protocol/ech/Encryption.h>
#include <fizz/protocol/ech/test/TestUtil.h>
#include <fizz/protocol/test/Mocks.h>
#include <fizz/protocol/test/TestMessages.h>

using namespace fizz::test;

namespace fizz {
namespace ech {
namespace test {

static constexpr folly::StringPiece expectedClientHelloInner{
    "030344444444444444444444444444444444444444444444444444444444444444440000041301130201000056002b0003020304000a00060004001d00170033000e000c001d00086b65797368617265000d00060004040308040000001500130000107777772e686f73746e616d652e636f6d001000050003026832002d0003020100"};
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

void checkDecodedChlo(ClientHello decodedChlo, ClientHello expectedChlo) {
  EXPECT_TRUE(folly::IOBufEqualTo()(
      decodedChlo.legacy_session_id, expectedChlo.legacy_session_id));
  EXPECT_EQ(decodedChlo.extensions.size(), expectedChlo.extensions.size());
  for (size_t extIndex = 0; extIndex < decodedChlo.extensions.size(); ++extIndex) {
    EXPECT_TRUE(folly::IOBufEqualTo()(
        decodedChlo.extensions[extIndex].extension_data,
        expectedChlo.extensions[extIndex].extension_data));
  }
  EXPECT_EQ(decodedChlo.random, expectedChlo.random);
  EXPECT_EQ(decodedChlo.cipher_suites, expectedChlo.cipher_suites);
  EXPECT_EQ(decodedChlo.legacy_compression_methods, expectedChlo.legacy_compression_methods);
}

EncryptedClientHello getTestECH(ClientHello chlo) {
  auto testCipherSuite = HpkeCipherSuite{hpke::KDFId::Sha256,
                                         hpke::AeadId::TLS_AES_128_GCM_SHA256};
  auto getTestConfig = [testCipherSuite]() {
    auto testConfigContent = getECHConfigContent();
    testConfigContent.cipher_suites = {testCipherSuite};
    auto publicKey = detail::encodeECPublicKey(getPublicKey(kP256PublicKey));
    testConfigContent.kem_id = hpke::KEMId::secp256r1;
    testConfigContent.public_key = std::move(publicKey);

    ECHConfig testConfig;
    testConfig.version = ECHVersion::V7;
    testConfig.ech_config_content = encode(std::move(testConfigContent));
    return testConfig;
  };

  SupportedECHConfig supportedConfig{getTestConfig(), testCipherSuite};

  auto kex = std::make_unique<MockOpenSSLECKeyExchange256>();
  auto privateKey = getPrivateKey(kP256Key);
  kex->setPrivateKey(std::move(privateKey));
  EXPECT_CALL(*kex, generateKeyPair()).Times(1);

  auto setupResult = constructHpkeSetupResult(std::move(kex), supportedConfig);
  return encryptClientHello(
      std::move(supportedConfig), std::move(chlo), std::move(setupResult));
}

TEST(EncryptionTest, TestValidECHConfigContent) {

  // Add config that doesn't work and cannot be supported
  ECHConfigContentDraft7 invalidConfigContent = getECHConfigContent();
  invalidConfigContent.kem_id = hpke::KEMId::secp521r1;
  std::vector<ECHConfig> configs;
  ECHConfig invalid;
  invalid.version = ECHVersion::V7;
  invalid.ech_config_content = encode(std::move(invalidConfigContent));

  // Add config that works and can be supported
  ECHConfig valid = getECHConfig();

  configs.push_back(std::move(invalid));
  configs.push_back(std::move(valid));

  std::vector<hpke::KEMId> supportedKEMs{hpke::KEMId::x25519,
                                         hpke::KEMId::secp256r1};
  std::vector<hpke::AeadId> supportedAeads{
      hpke::AeadId::TLS_AES_256_GCM_SHA384,
      hpke::AeadId::TLS_AES_128_GCM_SHA256};

  folly::Optional<SupportedECHConfig> result =
      selectECHConfig(configs, supportedKEMs, supportedAeads);
  EXPECT_TRUE(result.hasValue());

  ECHConfig gotConfig = std::move(result.value().config);
  EXPECT_TRUE(folly::IOBufEqualTo()(gotConfig.ech_config_content, encode(getECHConfigContent())));
  EXPECT_EQ(result.value().cipherSuite.kdfId, hpke::KDFId::Sha256);
  EXPECT_EQ(result.value().cipherSuite.aeadId, hpke::AeadId::TLS_AES_128_GCM_SHA256);
}

TEST(EncryptionTest, TestInvalidECHConfigContent) {
  ECHConfigContentDraft7 configContent = getECHConfigContent();

  configContent.kem_id = hpke::KEMId::secp256r1;
  HpkeCipherSuite suite{hpke::KDFId::Sha512, hpke::AeadId::TLS_AES_128_GCM_SHA256};
  std::vector<HpkeCipherSuite> cipher_suites = {suite};
  configContent.cipher_suites = cipher_suites;

  ECHConfig invalidConfig;
  invalidConfig.version = ECHVersion::V7;
  invalidConfig.ech_config_content = encode(std::move(configContent));

  std::vector<ECHConfig> configs;
  configs.push_back(std::move(invalidConfig));

  std::vector<hpke::KEMId> supportedKEMs{hpke::KEMId::x25519,
                                         hpke::KEMId::secp256r1};
  std::vector<hpke::AeadId> supportedAeads{
      hpke::AeadId::TLS_AES_128_GCM_SHA256};

  folly::Optional<SupportedECHConfig> result =
      selectECHConfig(configs, supportedKEMs, supportedAeads);

  EXPECT_FALSE(result.hasValue());
}

TEST(EncryptionTest, TestValidEncryptClientHello) {
  auto testCipherSuite = HpkeCipherSuite{hpke::KDFId::Sha256,
                                         hpke::AeadId::TLS_AES_128_GCM_SHA256};
  auto gotECH = getTestECH(TestMessages::clientHello());
  EXPECT_EQ(gotECH.suite.kdfId, testCipherSuite.kdfId);
  EXPECT_EQ(gotECH.suite.aeadId, testCipherSuite.aeadId);

  auto context = getContext(std::move(gotECH.enc));
  std::unique_ptr<folly::IOBuf> gotClientHelloInner = context.open(
      folly::IOBuf::copyBuffer("").get(), std::move(gotECH.encrypted_ch));

  EXPECT_TRUE(folly::IOBufEqualTo()(
      gotClientHelloInner, toIOBuf(expectedClientHelloInner)));

  EXPECT_TRUE(folly::IOBufEqualTo()(
      gotECH.record_digest, toIOBuf(expectedRecordDigest)));

  folly::io::Cursor encodedECHInnerCursor(gotClientHelloInner.get());
  auto decodedChlo = decode<ClientHello>(encodedECHInnerCursor);
  auto expectedChlo = TestMessages::clientHello();

  checkDecodedChlo(std::move(decodedChlo), std::move(expectedChlo));
}

TEST(EncryptionTest, TestTryToDecryptECH) {
  // This value comes from what was printed when we get the context exported value.
  auto nonceHex = "972a9c468ef0891fd22c052c6785f6a6";
  auto makeChloWithNonce = [nonceHex]() {
    auto testChlo = TestMessages::clientHello();
    auto nonceBuf = toIOBuf(nonceHex);
    auto nonceValueRange = nonceBuf->coalesce();
    std::array<uint8_t, 16> nonceValueArr;
    std::copy(
        nonceValueRange.begin(),
        nonceValueRange.begin() + 16,
        nonceValueArr.begin());
    ECHNonce echNonce{nonceValueArr};
    auto echNonceExt = encodeExtension(echNonce);
    testChlo.extensions.push_back(std::move(echNonceExt));
    return testChlo;
  };

  auto kex = std::make_unique<MockOpenSSLECKeyExchange256>();
  auto privateKey = getPrivateKey(kP256Key);
  kex->setPrivateKey(std::move(privateKey));

  auto testECH =  getTestECH(makeChloWithNonce());
  auto context = getContext(testECH.enc->clone());
  std::unique_ptr<folly::IOBuf> expectedNonceValue =
    context.exportSecret(folly::IOBuf::copyBuffer("tls13-ech-nonce"), 16);

  EXPECT_TRUE(folly::IOBufEqualTo()(expectedNonceValue, toIOBuf(nonceHex)));

  auto decodedChloResult = tryToDecryptECH(hpke::KEMId::secp256r1, std::move(testECH), std::move(kex));
  EXPECT_TRUE(decodedChloResult.has_value());
  EXPECT_TRUE(folly::IOBufEqualTo()(expectedNonceValue, toIOBuf(nonceHex)));

  checkDecodedChlo(std::move(decodedChloResult.value()), makeChloWithNonce());
}

} // namespace test
} // namespace ech
} // namespace fizz
