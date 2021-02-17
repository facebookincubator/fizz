/*
 *  Copyright (c) 2019-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/hpke/Types.h>
#include <fizz/record/Extensions.h>
#include <cstdint>
#include <vector>

namespace fizz {
namespace ech {

using Buf = std::unique_ptr<folly::IOBuf>;
using HpkePublicKey = Buf;
using HpkeNonce = std::array<uint8_t, 16>;

enum class ECHVersion : uint16_t {
  V7 = 0xff07,
  V8 = 0xfe08,
};

struct ECHCipherSuite {
  hpke::KDFId kdf_id;
  hpke::AeadId aead_id;
  bool operator==(const ECHCipherSuite& other) const {
    return kdf_id == other.kdf_id && aead_id == other.aead_id;
  }
};

struct ECHConfigContentDraft {
  Buf public_name;
  HpkePublicKey public_key;
  hpke::KEMId kem_id;
  std::vector<ECHCipherSuite> cipher_suites;
  uint16_t maximum_name_length;
  std::vector<Extension> extensions;
};

struct ECHConfig {
  ECHVersion version;
  uint16_t length;
  Buf ech_config_content;
  ECHConfig() {}
  ECHConfig(const ECHConfig& other) {
    version = other.version;
    length = other.length;
    ech_config_content = other.ech_config_content->clone();
  }
};

} // namespace ech
} // namespace fizz

#include <fizz/protocol/ech/Types-inl.h>
