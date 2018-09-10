/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <fizz/extensions/exportedauth/ExportedAuthenticator.h>
#include <fizz/record/Extensions.h>
#include <fizz/record/Types.h>
#include <folly/String.h>

using namespace folly;
using namespace folly::io;

using namespace testing;

namespace fizz {
namespace test {

StringPiece expected_auth_request = {
    "14303132333435363738396162636465666768696a000a000d0006000404030804"};

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

} // namespace test
} // namespace fizz
