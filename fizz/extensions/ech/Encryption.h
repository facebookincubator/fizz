/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/extensions/ech/Types.h>

namespace fizz {
namespace extensions {

struct SupportedECHConfig {
  ECHConfigContentDraft7 config;
  HpkeCipherSuite cipherSuite;
};

folly::Optional<SupportedECHConfig> selectECHConfig(std::vector<ECHConfigContentDraft7> configs,
  std::vector<hpke::KEMId> supportedKEMs, std::vector<hpke::KDFId>  supportedHashFunctions,
  std::vector<hpke::AeadId>  supportedCiphers);

} // namespace extensions
} // namespace fizz
