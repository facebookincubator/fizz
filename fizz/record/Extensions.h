/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/record/Types.h>
#include <folly/Optional.h>

namespace fizz {

struct SignatureAlgorithms {
  std::vector<SignatureScheme> supported_signature_algorithms;
};

struct SupportedGroups {
  std::vector<NamedGroup> named_group_list;
};

struct KeyShareEntry {
  NamedGroup group;
  Buf key_exchange;
};

struct ClientKeyShare {
  std::vector<KeyShareEntry> client_shares;

  bool preDraft23{false};
};

struct ServerKeyShare {
  KeyShareEntry server_share;

  bool preDraft23{false};
};

struct HelloRetryRequestKeyShare {
  NamedGroup selected_group;

  bool preDraft23{false};
};

struct PskIdentity {
  Buf psk_identity;
  uint32_t obfuscated_ticket_age;
};

struct PskBinder {
  Buf binder;
};

struct ClientPresharedKey {
  std::vector<PskIdentity> identities;
  std::vector<PskBinder> binders;
};

struct ServerPresharedKey {
  uint16_t selected_identity;
};

struct ClientEarlyData {};

struct ServerEarlyData {};

struct TicketEarlyData {
  uint32_t max_early_data_size;
};

struct Cookie {
  Buf cookie;
};

struct SupportedVersions {
  std::vector<ProtocolVersion> versions;
};

struct ServerSupportedVersions {
  ProtocolVersion selected_version;
};

struct PskKeyExchangeModes {
  std::vector<PskKeyExchangeMode> modes;
};

struct ProtocolName {
  Buf name;
};

struct ProtocolNameList {
  std::vector<ProtocolName> protocol_name_list;
};

enum class ServerNameType : uint8_t { host_name = 0 };

struct ServerName {
  ServerNameType name_type{ServerNameType::host_name};
  Buf hostname;
};

struct ServerNameList {
  std::vector<ServerName> server_name_list;

  bool useAlternateCodePoint{false};
};

struct DistinguishedName {
  Buf encoded_name;
};

struct CertificateAuthorities {
  std::vector<DistinguishedName> authorities;
};

template <class T>
folly::Optional<T> getExtension(const std::vector<Extension>& extension);

template <class T>
Extension encodeExtension(const T& t);

std::vector<Extension>::const_iterator findExtension(
    const std::vector<Extension>& extensions,
    ExtensionType type);

size_t getBinderLength(const ClientHello& chlo);
} // namespace fizz

#include <fizz/record/Extensions-inl.h>
