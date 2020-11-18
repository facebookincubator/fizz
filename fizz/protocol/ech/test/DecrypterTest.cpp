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

static ECHConfig constructECHConfigV7() {
  auto configContent = getECHConfigContent();
  configContent.public_key =
      detail::encodeECPublicKey(getPublicKey(kP256PublicKey));

  ECHConfig testConfig;
  testConfig.version = ECHVersion::V7;
  testConfig.ech_config_content = encode(std::move(configContent));
  return testConfig;
}

TEST(DecrypterTest, TestDecodeSuccess) {
  auto getClientHelloOuter = [](std::unique_ptr<KeyExchange> kex) {
    // Setup ECH extension
    auto supportedECHConfig = SupportedECHConfig{
        constructECHConfigV7(),
        HpkeCipherSuite{hpke::KDFId::Sha256,
                        hpke::AeadId::TLS_AES_128_GCM_SHA256}};
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
  decrypter.addDecryptionConfig(DecrypterParams{constructECHConfigV7(), kex->clone()});
  auto chloOuter = getClientHelloOuter(kex->clone());
  auto gotChlo = decrypter.decryptClientHello(chloOuter);

  EXPECT_TRUE(gotChlo.has_value());

  auto expectedChloInner = TestMessages::clientHello();
  EXPECT_FALSE(folly::IOBufEqualTo()(
      encodeHandshake(chloOuter), encodeHandshake(expectedChloInner)));

  auto chlo = std::move(gotChlo.value());
  TestMessages::removeExtension(chlo, ExtensionType::ech_nonce);
  EXPECT_TRUE(folly::IOBufEqualTo()(
      encodeHandshake(chlo), encodeHandshake(TestMessages::clientHello())));
}

TEST(DecrypterTest, TestDecodeFailure) {
  auto kex = std::make_unique<OpenSSLECKeyExchange<P256>>();
  kex->setPrivateKey(getPrivateKey(kP256Key));

  ECHConfigManager decrypter;
  decrypter.addDecryptionConfig(DecrypterParams{constructECHConfigV7(), kex->clone()});
  auto gotChlo = decrypter.decryptClientHello(TestMessages::clientHello());

  EXPECT_FALSE(gotChlo.has_value());
}

} // namespace test
} // namespace ech
} // namespace fizz
