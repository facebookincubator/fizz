/*
 *  Copyright (c) 2019-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */
#include <fizz/extensions/delegatedcred/DelegatedCredentialUtils.h>
#include <folly/ssl/OpenSSLCertUtils.h>

namespace fizz {
namespace extensions {

void DelegatedCredentialUtils::checkExtensions(
    const folly::ssl::X509UniquePtr& cert) {
  if (!hasDelegatedExtension(cert)) {
    throw FizzException(
        "cert is missing DelegationUsage extension",
        AlertDescription::illegal_parameter);
  }

  if ((X509_get_extension_flags(cert.get()) & EXFLAG_KUSAGE) != EXFLAG_KUSAGE) {
    throw FizzException(
        "cert is missing KeyUsage extension",
        AlertDescription::illegal_parameter);
  }

  auto key_usage = X509_get_key_usage(cert.get());
  if ((key_usage & KU_DIGITAL_SIGNATURE) != KU_DIGITAL_SIGNATURE) {
    throw FizzException(
        "cert lacks digital signature key usage",
        AlertDescription::illegal_parameter);
  }
}

namespace {
static constexpr folly::StringPiece kDelegatedOid{"1.3.6.1.4.1.44363.44"};

folly::ssl::ASN1ObjUniquePtr generateCredentialOid() {
  folly::ssl::ASN1ObjUniquePtr oid;
  oid.reset(OBJ_txt2obj(kDelegatedOid.data(), 1));
  if (!oid) {
    throw std::runtime_error("Couldn't create OID for delegated credential");
  }
  return oid;
}
} // namespace

bool DelegatedCredentialUtils::hasDelegatedExtension(
    const folly::ssl::X509UniquePtr& cert) {
  static folly::ssl::ASN1ObjUniquePtr credentialOid = generateCredentialOid();
  // To be valid for a credential, it has to have the delegated credential
  // extension and the digitalSignature KeyUsage.
  auto credentialIdx = X509_get_ext_by_OBJ(cert.get(), credentialOid.get(), -1);
  if (credentialIdx == -1) {
    return false;
  }

  return true;
}

Buf DelegatedCredentialUtils::prepareSignatureBuffer(
    const DelegatedCredential& cred,
    Buf certData) {
  auto toSign = folly::IOBuf::create(0);
  folly::io::Appender appender(toSign.get(), 10);
  appender.pushAtMost(certData->data(), certData->length());
  detail::write(cred.valid_time, appender);
  detail::write(cred.expected_verify_scheme, appender);
  detail::writeBuf<detail::bits24>(cred.public_key, appender);
  detail::write(cred.credential_scheme, appender);
  return toSign;
}
} // namespace extensions
} // namespace fizz
