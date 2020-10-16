/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/exchange/KeyExchange.h>
#include <fizz/extensions/ech/Types.h>
#include <fizz/extensions/ech/ECHExtensions.h>

namespace fizz {
namespace extensions {

struct SupportedECHConfig {
  ECHConfigContentDraft7 config;
  HpkeCipherSuite cipherSuite;
};

folly::Optional<SupportedECHConfig> selectECHConfig(std::vector<ECHConfigContentDraft7> configs,
  std::vector<hpke::KEMId> supportedKEMs, std::vector<hpke::KDFId>  supportedHashFunctions,
  std::vector<hpke::AeadId>  supportedCiphers);

EncryptedClientHello encryptClientHello(
  std::unique_ptr<KeyExchange> kex, SupportedECHConfig supportedConfig, ClientHello clientHello);

} // namespace extensions
} // namespace fizz
