/*
 *  Copyright (c) 2019-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/record/Types.h>
#include <vector>

namespace fizz {
template <>
inline Extension encodeExtension(const ech::EncryptedClientHello& ech) {
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
inline Extension encodeExtension(const ech::ECHNonce& echNonce) {
  Extension ext;
  ext.extension_type = ExtensionType::ech_nonce;
  ext.extension_data = folly::IOBuf::create(16);

  folly::io::Appender appender(ext.extension_data.get(), 0);
  detail::write(echNonce.nonce, appender);

  return ext;
}

template <>
inline Extension encodeExtension(const ech::ClientECH& clientECH) {
  Extension ext;
  ext.extension_type = ExtensionType::encrypted_client_hello;
  ext.extension_data = folly::IOBuf::create(0);

  folly::io::Appender appender(ext.extension_data.get(), 20);
  detail::write(clientECH.cipher_suite, appender);
  detail::writeBuf<uint16_t>(clientECH.config_id, appender);
  detail::writeBuf<uint16_t>(clientECH.enc, appender);
  detail::writeBuf<uint16_t>(clientECH.payload, appender);

  return ext;
}

template <>
inline ech::EncryptedClientHello getExtension(folly::io::Cursor& cs) {
  ech::EncryptedClientHello ech;
  detail::read(ech.suite, cs);
  detail::readBuf<uint16_t>(ech.record_digest, cs);
  detail::readBuf<uint16_t>(ech.enc, cs);
  detail::readBuf<uint16_t>(ech.encrypted_ch, cs);

  return ech;
}

template <>
inline ech::ECHNonce getExtension(folly::io::Cursor& cs) {
  ech::ECHNonce echNonce;
  detail::read(echNonce.nonce, cs);
  return echNonce;
}

template <>
inline ech::ClientECH getExtension(folly::io::Cursor& cs) {
  ech::ClientECH clientECH;
  detail::read(clientECH.cipher_suite, cs);
  detail::readBuf<uint16_t>(clientECH.config_id, cs);
  detail::readBuf<uint16_t>(clientECH.enc, cs);
  detail::readBuf<uint16_t>(clientECH.payload, cs);

  return clientECH;
}
} // namespace fizz
