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
ClientHello getChloOuterWithExt(std::unique_ptr<KeyExchange> kex) {
  // Setup ECH extension
  auto supportedECHConfig = SupportedECHConfig{
      getECHConfig(),
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

  ClientECH echExt =
      encryptClientHello(supportedECHConfig, chloInner, chloOuter, setupResult);

  // Add ECH extension
  chloOuter.extensions.push_back(encodeExtension(echExt));

  return chloOuter;
}

TEST(DecrypterTest, TestDecodeSuccess) {
  auto kex = std::make_unique<OpenSSLECKeyExchange<P256>>();
  kex->setPrivateKey(getPrivateKey(kP256Key));

  ECHConfigManager decrypter;
  decrypter.addDecryptionConfig(DecrypterParams{getECHConfig(), kex->clone()});
  auto chloOuter = getChloOuterWithExt(kex->clone());
  auto gotChlo = decrypter.decryptClientHello(chloOuter);

  EXPECT_TRUE(gotChlo.has_value());

  auto expectedChloInner = TestMessages::clientHello();
  EXPECT_FALSE(folly::IOBufEqualTo()(
      encodeHandshake(chloOuter), encodeHandshake(expectedChloInner)));

  auto chlo = std::move(gotChlo.value());
  // Remove the inner ECH extension from the client hello inner
  TestMessages::removeExtension(chlo, ExtensionType::ech_is_inner);

  EXPECT_TRUE(folly::IOBufEqualTo()(
      encodeHandshake(chlo), encodeHandshake(expectedChloInner)));
}

TEST(DecrypterTest, TestDecodeFailure) {
  auto echConfig = getECHConfig();
  auto kex = std::make_unique<OpenSSLECKeyExchange<P256>>();
  kex->setPrivateKey(getPrivateKey(kP256Key));

  ECHConfigManager decrypter;
  decrypter.addDecryptionConfig(
      DecrypterParams{std::move(echConfig), kex->clone()});
  auto gotChlo = decrypter.decryptClientHello(TestMessages::clientHello());

  EXPECT_FALSE(gotChlo.has_value());
}

} // namespace test
} // namespace ech
} // namespace fizz
