/*
 *  Copyright (c) 2019-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/protocol/ech/Types.h>
#include <folly/io/Cursor.h>

namespace fizz {
template <>
struct detail::Writer<ech::HpkeNonce> {
  template <class T>
  void write(const std::array<uint8_t, 16>& arr, folly::io::Appender& out) {
    out.push(arr.data(), arr.size());
  }
};

template <>
inline void detail::write<ech::ECHConfig>(
    const ech::ECHConfig& echConfig,
    folly::io::Appender& out) {
  detail::write(echConfig.version, out);
  detail::write(echConfig.length, out);
  detail::writeBufWithoutLength(echConfig.ech_config_content, out);
}

template <>
inline void detail::write<ech::ECHCipherSuite>(
    const ech::ECHCipherSuite& suite,
    folly::io::Appender& out) {
  detail::write(suite.kdf_id, out);
  detail::write(suite.aead_id, out);
}

template <>
struct detail::Sizer<ech::ECHConfig> {
  template <class T>
  size_t getSize(const ech::ECHConfig& proto) {
    return sizeof(uint16_t) + sizeof(uint16_t) + proto.length;
  }
};

template <>
struct detail::Sizer<ech::ECHCipherSuite> {
  template <class T>
  size_t getSize(const ech::ECHCipherSuite&) {
    return sizeof(uint16_t) + sizeof(uint16_t);
  }
};

template <>
struct detail::Reader<ech::ECHCipherSuite> {
  template <class T>
  size_t read(ech::ECHCipherSuite& suite, folly::io::Cursor& cursor) {
    size_t len = detail::read(suite.kdf_id, cursor) +
        detail::read(suite.aead_id, cursor);
    return len;
  }
};

template <>
struct detail::Reader<ech::ECHConfig> {
  template <class T>
  size_t read(ech::ECHConfig& echConfig, folly::io::Cursor& cursor) {
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
inline Buf encode<ech::ECHConfigContentDraft>(
    ech::ECHConfigContentDraft&& ech) {
  auto buf = folly::IOBuf::create(
      detail::getBufSize<uint16_t>(ech.public_name) +
      detail::getBufSize<uint16_t>(ech.public_key) + sizeof(uint16_t) +
      sizeof(ech::ECHCipherSuite) * ech.cipher_suites.size() +
      sizeof(uint16_t) + 20);

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
inline Buf encode<const ech::ECHConfig&>(const ech::ECHConfig& echConfig) {
  auto buf = folly::IOBuf::create(
      sizeof(uint16_t) + sizeof(uint16_t) +
      detail::getBufSize<uint16_t>(echConfig.ech_config_content));

  folly::io::Appender appender(buf.get(), 20);
  detail::write(echConfig.version, appender);
  detail::write(echConfig.length, appender);
  detail::writeBuf<uint16_t>(echConfig.ech_config_content, appender);

  return buf;
}

template <>
inline Buf encode<ech::ECHConfig>(ech::ECHConfig&& echConfig) {
  return encode<const ech::ECHConfig&>(echConfig);
}

template <>
inline ech::ECHConfigContentDraft decode(folly::io::Cursor& cursor) {
  ech::ECHConfigContentDraft echConfigContent;
  detail::readBuf<uint16_t>(echConfigContent.public_name, cursor);
  detail::readBuf<uint16_t>(echConfigContent.public_key, cursor);
  detail::read(echConfigContent.kem_id, cursor);
  detail::readVector<uint16_t>(echConfigContent.cipher_suites, cursor);
  detail::read<uint16_t>(echConfigContent.maximum_name_length, cursor);
  detail::readVector<uint16_t>(echConfigContent.extensions, cursor);

  return echConfigContent;
}

template <>
inline ech::ECHConfig decode(folly::io::Cursor& cursor) {
  ech::ECHConfig echConfig;
  detail::read(echConfig.version, cursor);
  detail::read<uint16_t>(echConfig.length, cursor);
  detail::readBuf<uint16_t>(echConfig.ech_config_content, cursor);

  return echConfig;
}
} // namespace fizz
