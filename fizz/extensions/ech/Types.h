/*
 *  Copyright (c) 2019-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <vector>
#include <cstdint>
#include <fizz/record/Extensions.h>

namespace fizz {
namespace extensions {

using Buf = std::unique_ptr<folly::IOBuf>;
using HpkePublicKey = Buf;
using HkpeKemId = uint16_t;
using HkpeAeadId = uint16_t;
using HkpeKdfId = uint16_t;
using HpkeNonce = std::array<uint8_t, 16>;

struct HpkeCipherSuite {
    HkpeKdfId kdfId;
    HkpeAeadId aeadId;
};

struct ECHConfigContentDraft7 {
    Buf public_name;
    HpkePublicKey public_key;
    HkpeKemId kem_id;
    std::vector<HpkeCipherSuite> cipher_suites;
    uint16_t maximum_name_length;
    std::vector<Extension> extensions;
};


struct ECHConfig {
    uint16_t version;
    uint16_t length;
    Buf ech_config_content;
};

} // namespace extensions
} // namespace fizz

#include <fizz/extensions/ech/Types-inl.h>
