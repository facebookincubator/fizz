/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <fizz/crypto/test/TestUtil.h>
#include <fizz/extensions/exportedauth/ExportedAuthenticator.h>
#include <fizz/protocol/test/Mocks.h>
#include <fizz/protocol/test/TestMessages.h>
#include <fizz/record/Extensions.h>
#include <fizz/record/Types.h>
#include <folly/String.h>
#include <folly/ssl/Init.h>

using namespace folly;
using namespace folly::io;

using namespace testing;

namespace fizz {
namespace test {

StringPiece expected_auth_request = {
    "14303132333435363738396162636465666768696a000a000d0006000404030804"};
StringPiece expected_authenticator = {
    "0b000004000000000f00000d040300097369676e617475726514000020b523548c421b05f7f3c33276fbdd5266ba2df103796d7d483368259860a648f2"};
StringPiece expected_empty_authenticator = {
    "1400002011fae4bcdf4673b6dfb276d886c4cd1c5b0920da961643f062d1d4a6062115b1"};

TEST(ExportedAuthenticatorTest, TestAuthenticatorRequest) {
  auto buf = folly::IOBuf::copyBuffer(unhexlify(expected_auth_request));
  folly::io::Cursor cursor(buf.get());
  CertificateRequest cr = decode<CertificateRequest>(cursor);
  EXPECT_EQ(cr.certificate_request_context->computeChainDataLength(), 20);
  EXPECT_EQ(cr.extensions.size(), 1);
  EXPECT_TRUE(getExtension<SignatureAlgorithms>(cr.extensions).hasValue());
  auto encodedAuthRequest = ExportedAuthenticator::getAuthenticatorRequest(
      std::move(cr.certificate_request_context), std::move(cr.extensions));
  EXPECT_EQ(
      expected_auth_request,
      StringPiece(hexlify(encodedAuthRequest->coalesce())));
}

TEST(ExportedAuthenticatorTest, TestEmptyAuthenticatorRequest) {
  EXPECT_THROW(
      ExportedAuthenticator::getAuthenticatorRequest(
          nullptr, std::vector<fizz::Extension>()),
      FizzException);
  auto emptyContext = folly::IOBuf::create(0);
  EXPECT_THROW(
      ExportedAuthenticator::getAuthenticatorRequest(
          std::move(emptyContext), std::vector<fizz::Extension>()),
      FizzException);
}

class AuthenticatorTest : public ::testing::Test {
 public:
  void SetUp() override {
    folly::ssl::init();
    CertificateRequest cr;
    cr.certificate_request_context =
        folly::IOBuf::copyBuffer("0123456789abcdefghij");
    SignatureAlgorithms sigAlgs;
    sigAlgs.supported_signature_algorithms.push_back(
        SignatureScheme::ecdsa_secp256r1_sha256);
    cr.extensions.push_back(encodeExtension(std::move(sigAlgs)));
    auto authRequest = encode<CertificateRequest>(std::move(cr));
    authrequest_ = std::move(authRequest);
    CipherSuite cipher = CipherSuite::TLS_AES_128_GCM_SHA256;
    deriver_ = Factory().makeKeyDeriver(cipher);
    handshakeContext_ =
        folly::IOBuf::copyBuffer("12345678901234567890123456789012");
    finishedKey_ = folly::IOBuf::copyBuffer("12345678901234567890123456789012");
    schemes_.push_back(SignatureScheme::ecdsa_secp256r1_sha256);
  }

 protected:
  std::unique_ptr<KeyDerivation> deriver_;
  std::vector<SignatureScheme> schemes_;
  Buf authrequest_;
  Buf handshakeContext_;
  Buf finishedKey_;
};

TEST_F(AuthenticatorTest, TestValidAuthenticator) {
  auto mockCert = std::make_shared<MockSelfCert>();
  EXPECT_CALL(*mockCert, _getCertMessage(_)).WillOnce(InvokeWithoutArgs([]() {
    return TestMessages::certificate();
  }));
  EXPECT_CALL(*mockCert, getSigSchemes())
      .WillOnce(Return(std::vector<SignatureScheme>(
          1, SignatureScheme::ecdsa_secp256r1_sha256)));
  EXPECT_CALL(*mockCert, sign(_, CertificateVerifyContext::Authenticator, _))
      .WillOnce(
          InvokeWithoutArgs([]() { return IOBuf::copyBuffer("signature"); }));

  auto reencodedAuthenticator = ExportedAuthenticator::makeAuthenticator(
      deriver_,
      schemes_,
      *mockCert,
      std::move(authrequest_),
      std::move(handshakeContext_),
      std::move(finishedKey_),
      CertificateVerifyContext::Authenticator);
  EXPECT_EQ(
      expected_authenticator,
      (StringPiece(hexlify(reencodedAuthenticator->coalesce()))));
}

TEST_F(AuthenticatorTest, TestEmptyAuthenticator) {
  auto mockCert = std::make_shared<MockSelfCert>();
  EXPECT_CALL(*mockCert, getSigSchemes())
      .WillOnce(Return(std::vector<SignatureScheme>(
          1, SignatureScheme::ecdsa_secp256r1_sha256)));
  schemes_.clear();
  auto reencodedAuthenticator = ExportedAuthenticator::makeAuthenticator(
      deriver_,
      schemes_,
      *mockCert,
      std::move(authrequest_),
      std::move(handshakeContext_),
      std::move(finishedKey_),
      CertificateVerifyContext::Authenticator);
  EXPECT_EQ(
      expected_empty_authenticator,
      StringPiece(hexlify(reencodedAuthenticator->coalesce())));
}

} // namespace test
} // namespace fizz
