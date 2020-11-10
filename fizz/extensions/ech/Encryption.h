/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/exchange/KeyExchange.h>
#include <fizz/crypto/hpke/Hpke.h>
#include <fizz/extensions/ech/Types.h>
#include <fizz/extensions/ech/ECHExtensions.h>

namespace fizz {
namespace extensions {

struct SupportedECHConfig {
  ECHConfig config;
  HpkeCipherSuite cipherSuite;
};

folly::Optional<SupportedECHConfig> selectECHConfig(
    std::vector<ECHConfig> configs,
    std::vector<hpke::KEMId> supportedKEMs,
    std::vector<hpke::AeadId> supportedAeads);

void addECHNonceExtensionToClientHello(
    const hpke::HpkeContext& context,
    ClientHello& clientHello);

hpke::SetupResult constructHpkeSetupResult(
    std::unique_ptr<KeyExchange> kex,
    const SupportedECHConfig& supportedConfig);

EncryptedClientHello encryptClientHello(
    const SupportedECHConfig& supportedConfig,
    ClientHello clientHello,
    hpke::SetupResult setupResult);

} // namespace extensions
} // namespace fizz
