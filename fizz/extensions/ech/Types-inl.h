/*
 *  Copyright (c) 2019-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/extensions/ech/Types.h>
#include <folly/io/Cursor.h>

namespace fizz {
template <>
struct detail::Writer<extensions::HpkeNonce> {
  template <class T>
  void write(const std::array<uint8_t, 16>& arr, folly::io::Appender& out) {
    out.push(arr.data(), arr.size());
  }
};

template <>
inline void detail::write<extensions::ECHConfig>(
    const extensions::ECHConfig& echConfig,
    folly::io::Appender& out) {
  detail::write(echConfig.version, out);
  detail::write(echConfig.length, out);
  detail::writeBuf<uint16_t>(echConfig.ech_config_content, out);
}

template <>
inline void detail::write<extensions::HpkeCipherSuite>(
  const extensions::HpkeCipherSuite& suite, folly::io::Appender& out) {
  detail::write(suite.kdfId, out);
  detail::write(suite.aeadId, out);
}

template <>
struct detail::Sizer<extensions::ECHConfig> {
  template <class T>
  size_t getSize(const extensions::ECHConfig& proto) {
    return sizeof(uint16_t) + sizeof(uint16_t) + detail::getBufSize<uint16_t>(proto.ech_config_content);
  }
};

template <>
struct detail::Sizer<extensions::HpkeCipherSuite> {
  template <class T>
  size_t getSize(const extensions::HpkeCipherSuite& proto) {
    return sizeof(uint16_t) + sizeof(uint16_t);
  }
};

template <>
struct detail::Reader<extensions::HpkeCipherSuite> {
  template <class T>
  size_t read(extensions::HpkeCipherSuite& suite, folly::io::Cursor& cursor) {
    size_t len = detail::read(suite.kdfId, cursor) + detail::read(suite.aeadId, cursor);
    return len;
  }
};

template <>
struct detail::Reader<extensions::ECHConfig> {
  template <class T>
  size_t read(extensions::ECHConfig& echConfig, folly::io::Cursor& cursor) {
    size_t len = 0;
    len += detail::read(echConfig.version, cursor);
    len += detail::read(echConfig.length, cursor);
    len += readBuf<uint16_t>(echConfig.ech_config_content, cursor);
    return len;
  }
};

template <>
struct detail::Reader<std::array<uint8_t, 16>> {
  template <class T>
  size_t read(std::array<uint8_t, 16>& out, folly::io::Cursor& cursor) {
    cursor.pull(out.data(), out.size());
    return out.size();
  }
};

template <>
inline Buf encode<extensions::ECHConfigContentDraft7>(extensions::ECHConfigContentDraft7&& ech) {
  auto buf = folly::IOBuf::create(
    detail::getBufSize<uint16_t>(ech.public_name)
    + detail::getBufSize<uint16_t>(ech.public_key)
    + sizeof(uint16_t)
    + sizeof(extensions::HpkeCipherSuite) * ech.cipher_suites.size()
    + sizeof(uint16_t)
    + 20);

  folly::io::Appender appender(buf.get(), 20);
  detail::writeBuf<uint16_t>(ech.public_name, appender);
  detail::writeBuf<uint16_t>(ech.public_key, appender);
  detail::write(ech.kem_id, appender);
  detail::writeVector<uint16_t>(ech.cipher_suites, appender);
  detail::write(ech.maximum_name_length, appender);
  detail::writeVector<uint16_t>(ech.extensions, appender);
  return buf;
}

template <>
inline Buf encode<extensions::ECHConfig>(extensions::ECHConfig&& echConfig) {
  auto buf = folly::IOBuf::create(
    sizeof(uint16_t)
    + sizeof(uint16_t)
    + detail::getBufSize<uint16_t>(echConfig.ech_config_content));

  folly::io::Appender appender(buf.get(), 20);
  detail::write(echConfig.version, appender);
  detail::write(echConfig.length, appender);
  detail::writeBuf<uint16_t>(echConfig.ech_config_content, appender);

  return buf;
}

template <>
inline extensions::ECHConfigContentDraft7 decode(folly::io::Cursor& cursor) {
  extensions::ECHConfigContentDraft7 echConfigContent;
  detail::readBuf<uint16_t>(echConfigContent.public_name, cursor);
  detail::readBuf<uint16_t>(echConfigContent.public_key, cursor);
  detail::read(echConfigContent.kem_id, cursor);
  detail::readVector<uint16_t>(echConfigContent.cipher_suites, cursor);
  detail::read<uint16_t>(echConfigContent.maximum_name_length, cursor);
  detail::readVector<uint16_t>(echConfigContent.extensions, cursor);

  return echConfigContent;
}

template <>
inline extensions::ECHConfig decode(folly::io::Cursor& cursor) {
  extensions::ECHConfig echConfig;
  detail::read(echConfig.version, cursor);
  detail::read<uint16_t>(echConfig.length, cursor);
  detail::readBuf<uint16_t>(echConfig.ech_config_content, cursor);

  return echConfig;
}
} // namespace fizz
