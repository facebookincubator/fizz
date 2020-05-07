/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/extensions/delegatedcred/SelfDelegatedCredential.h>

#include <folly/io/async/test/MockAsyncTransport.h>

namespace fizz {
namespace extensions {
namespace test {

/* using override */
using namespace testing;

class MockSelfDelegatedCredential : public SelfDelegatedCredential {
 public:
  MOCK_CONST_METHOD0(getIdentity, std::string());
  MOCK_CONST_METHOD0(getAltIdentities, std::vector<std::string>());
  MOCK_CONST_METHOD0(getSigSchemes, std::vector<SignatureScheme>());
  MOCK_CONST_METHOD0(_getDelegatedCredential, const DelegatedCredential&());

  const DelegatedCredential& getDelegatedCredential() const override {
    return _getDelegatedCredential();
  }

  MOCK_CONST_METHOD1(_getCertMessage, CertificateMsg(Buf&));
  CertificateMsg getCertMessage(Buf buf) const override {
    return _getCertMessage(buf);
  }
  MOCK_CONST_METHOD1(
      getCompressedCert,
      CompressedCertificate(CertificateCompressionAlgorithm));

  MOCK_CONST_METHOD3(
      sign,
      Buf(SignatureScheme scheme,
          CertificateVerifyContext context,
          folly::ByteRange toBeSigned));
  MOCK_CONST_METHOD0(getX509, folly::ssl::X509UniquePtr());
};

} // namespace test
} // namespace extensions
} // namespace fizz
