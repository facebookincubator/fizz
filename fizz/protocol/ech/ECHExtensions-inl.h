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
inline Extension encodeExtension(const ech::ClientECH& clientECH) {
  Extension ext;
  ext.extension_type = ExtensionType::encrypted_client_hello;
  ext.extension_data = folly::IOBuf::create(0);

  folly::io::Appender appender(ext.extension_data.get(), 20);
  detail::write(clientECH.cipher_suite, appender);
  detail::writeBuf<uint8_t>(clientECH.config_id, appender);
  detail::writeBuf<uint16_t>(clientECH.enc, appender);
  detail::writeBuf<uint16_t>(clientECH.payload, appender);

  return ext;
}

template <>
inline ech::ClientECH getExtension(folly::io::Cursor& cs) {
  ech::ClientECH clientECH;
  detail::read(clientECH.cipher_suite, cs);
  detail::readBuf<uint8_t>(clientECH.config_id, cs);
  detail::readBuf<uint16_t>(clientECH.enc, cs);
  detail::readBuf<uint16_t>(clientECH.payload, cs);

  return clientECH;
}
} // namespace fizz
