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
#include <fizz/protocol/Factory.h>
#include <fizz/protocol/ech/ECHExtensions.h>
#include <fizz/protocol/ech/Types.h>

namespace fizz {
namespace ech {

struct SupportedECHConfig {
  ECHConfig config;
  ECHCipherSuite cipherSuite;
};

folly::Optional<SupportedECHConfig> selectECHConfig(
    const std::vector<ECHConfig>& configs,
    std::vector<hpke::KEMId> supportedKEMs,
    std::vector<hpke::AeadId> supportedAeads);

ech::ECHNonce createNonceExtension(const hpke::HpkeContext& context);

hpke::SetupResult constructHpkeSetupResult(
    std::unique_ptr<KeyExchange> kex,
    const SupportedECHConfig& supportedConfig);

EncryptedClientHello encryptClientHello(
    const SupportedECHConfig& supportedConfig,
    ClientHello clientHello,
    hpke::SetupResult setupResult);

ClientECH encryptClientHelloV8(
    const SupportedECHConfig& supportedConfig,
    const ClientHello& clientHelloInner,
    const ClientHello& clientHelloOuter,
    hpke::SetupResult setupResult);

folly::Optional<ClientHello> tryToDecryptECH(
    const ClientHello& clientHelloOuter,
    const ECHConfig& echConfig,
    ECHCipherSuite cipherSuite,
    std::unique_ptr<folly::IOBuf> encapsulatedKey,
    std::unique_ptr<folly::IOBuf> encryptedCh,
    std::unique_ptr<KeyExchange> kex,
    ECHVersion version);

std::unique_ptr<folly::IOBuf> constructConfigId(
    hpke::KDFId kdfId,
    ECHConfig echConfig);

std::unique_ptr<folly::IOBuf> getRecordDigest(
    const ECHConfig& echConfig,
    hpke::KDFId id);

} // namespace ech
} // namespace fizz
