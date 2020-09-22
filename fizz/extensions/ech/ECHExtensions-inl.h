/*
 *  Copyright (c) 2019-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <vector>
#include <fizz/record/Types.h>

namespace fizz {
template <>
inline Extension encodeExtension(const extensions::EncryptedClientHello &ech) {
  Extension ext;
  ext.extension_type = ExtensionType::encrypted_client_hello;
  ext.extension_data = folly::IOBuf::create(0);

  folly::io::Appender appender(ext.extension_data.get(), 20);
  detail::write(ech.suite, appender);
  detail::writeBuf<uint16_t>(ech.record_digest, appender);
  detail::writeBuf<uint16_t>(ech.enc, appender);
  detail::writeBuf<uint16_t>(ech.encrypted_ch, appender);

  return ext;
}

template <>
inline Extension encodeExtension(const extensions::ECHNonce &echNonce) {
  Extension ext;
  ext.extension_type = ExtensionType::ech_nonce;
  ext.extension_data = folly::IOBuf::create(16);

  folly::io::Appender appender(ext.extension_data.get(), 0);
  detail::write(echNonce.nonce, appender);

  return ext;
}

template <>
inline extensions::EncryptedClientHello getExtension(folly::io::Cursor& cs) {
  extensions::EncryptedClientHello ech;
  detail::read(ech.suite, cs);
  detail::readBuf<uint16_t>(ech.record_digest, cs);
  detail::readBuf<uint16_t>(ech.enc, cs);
  detail::readBuf<uint16_t>(ech.encrypted_ch, cs);

  return ech;
}

template <>
inline extensions::ECHNonce getExtension(folly::io::Cursor& cs) {
  extensions::ECHNonce echNonce;
  detail::read(echNonce.nonce, cs);
  return echNonce;
}
} // namespace extensions
