/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <fizz/crypto/test/TestUtil.h>
#include <fizz/protocol/ech/Decrypter.h>
#include <fizz/protocol/ech/test/TestUtil.h>
#include <fizz/protocol/test/TestMessages.h>

using namespace fizz::test;

namespace fizz {
namespace ech {
namespace test {

namespace {
ECHConfig constructECHConfigV7() {
  auto configContent = getECHConfigContent();
  configContent.public_key =
      detail::encodeECPublicKey(getPublicKey(kP256PublicKey));

  ECHConfig testConfig;
  testConfig.version = ECHVersion::V7;
  testConfig.ech_config_content = encode(std::move(configContent));
  testConfig.length = testConfig.ech_config_content->computeChainDataLength();
  return testConfig;
}

void checkDecryptionResult(
    folly::Optional<ClientHello> gotChlo,
    const std::unique_ptr<folly::IOBuf>& chloOuterHandshake,
    ECHVersion version) {
  EXPECT_TRUE(gotChlo.has_value());

  auto expectedChloInner = TestMessages::clientHello();
  EXPECT_FALSE(folly::IOBufEqualTo()(
      chloOuterHandshake, encodeHandshake(expectedChloInner)));

  auto chlo = std::move(gotChlo.value());
  if (version == ECHVersion::V7) {
    TestMessages::removeExtension(chlo, ExtensionType::ech_nonce);
  } else if (version == ECHVersion::V8) {
    // Remove the empty ECH extension from the client hello inner
    TestMessages::removeExtension(chlo, ExtensionType::encrypted_client_hello);
  }

  EXPECT_TRUE(folly::IOBufEqualTo()(
      encodeHandshake(chlo), encodeHandshake(expectedChloInner)));
}

} // namespace

TEST(DecrypterTest, TestDecodeSuccess) {
  auto getClientHelloOuter = [](std::unique_ptr<KeyExchange> kex) {
    // Setup ECH extension
    auto supportedECHConfig = SupportedECHConfig{
        constructECHConfigV7(),
        ECHCipherSuite{
            hpke::KDFId::Sha256, hpke::AeadId::TLS_AES_128_GCM_SHA256}};
    auto setupResult =
        constructHpkeSetupResult(std::move(kex), supportedECHConfig);

    // Add nonce extension
    auto chloInner = TestMessages::clientHello();
    chloInner.extensions.push_back(
        encodeExtension(createNonceExtension(setupResult.context)));

    // Encrypt client hello
    EncryptedClientHello echExt = encryptClientHello(
        supportedECHConfig, std::move(chloInner), std::move(setupResult));

    // Add ECH extension
    ClientHello chloOuter;
    chloOuter.extensions.push_back(encodeExtension(echExt));

    return chloOuter;
  };

  auto kex = std::make_unique<OpenSSLECKeyExchange<P256>>();
  kex->setPrivateKey(getPrivateKey(kP256Key));

  ECHConfigManager decrypter;
  decrypter.addDecryptionConfig(
      DecrypterParams{constructECHConfigV7(), kex->clone()});
  auto chloOuter = getClientHelloOuter(kex->clone());
  auto gotChlo = decrypter.decryptClientHello(chloOuter);

  checkDecryptionResult(
      std::move(gotChlo), encodeHandshake(chloOuter), ECHVersion::V7);
}

TEST(DecrypterTest, TestDecodeSuccessV8) {
  auto getChloOuterWithExt = [](std::unique_ptr<KeyExchange> kex) {
    // Setup ECH extension
    auto supportedECHConfig = SupportedECHConfig{
        getECHConfigV8(),
        ECHCipherSuite{
            hpke::KDFId::Sha256, hpke::AeadId::TLS_AES_128_GCM_SHA256}};
    auto setupResult =
        constructHpkeSetupResult(std::move(kex), supportedECHConfig);

    // Add empty ECH extension to client hello inner
    auto chloInner = TestMessages::clientHello();
    ClientECH chloInnerECHExt;
    chloInner.extensions.push_back(encodeExtension(chloInnerECHExt));

    // Encrypt client hello
    ClientHello chloOuter = getClientHelloOuter();
    chloOuter.legacy_session_id = folly::IOBuf::create(0);

    ClientECH echExt = encryptClientHelloV8(
        supportedECHConfig, chloInner, chloOuter, std::move(setupResult));

    // Add ECH extension
    chloOuter.extensions.push_back(encodeExtension(echExt));

    return chloOuter;
  };

  auto kex = std::make_unique<OpenSSLECKeyExchange<P256>>();
  kex->setPrivateKey(getPrivateKey(kP256Key));

  ECHConfigManager decrypter;
  decrypter.addDecryptionConfig(
      DecrypterParams{getECHConfigV8(), kex->clone()});
  auto chloOuter = getChloOuterWithExt(kex->clone());
  auto gotChlo = decrypter.decryptClientHello(chloOuter);

  checkDecryptionResult(
      std::move(gotChlo), encodeHandshake(chloOuter), ECHVersion::V8);
}

void testFailure(ECHConfig echConfig) {
  auto kex = std::make_unique<OpenSSLECKeyExchange<P256>>();
  kex->setPrivateKey(getPrivateKey(kP256Key));

  ECHConfigManager decrypter;
  decrypter.addDecryptionConfig(
      DecrypterParams{std::move(echConfig), kex->clone()});
  auto gotChlo = decrypter.decryptClientHello(TestMessages::clientHello());

  EXPECT_FALSE(gotChlo.has_value());
}

TEST(DecrypterTest, TestDecodeFailure) {
  testFailure(constructECHConfigV7());
  testFailure(getECHConfigV8());
}

} // namespace test
} // namespace ech
} // namespace fizz
