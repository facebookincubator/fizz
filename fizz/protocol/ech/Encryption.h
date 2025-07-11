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

struct NegotiatedECHConfig {
  ParsedECHConfig config;
  uint8_t configId;
  uint16_t maxLen;
  HpkeSymmetricCipherSuite cipherSuite;
};

// Used to indicate to the Decrypter that extension expansion failed (which is
// a hard error)
class OuterExtensionsError : public std::runtime_error {
 public:
  explicit OuterExtensionsError(const std::string& what)
      : std::runtime_error(what) {}
};

folly::Optional<NegotiatedECHConfig> negotiateECHConfig(
    const std::vector<ParsedECHConfig>& configs,
    std::vector<hpke::KEMId> supportedKEMs,
    std::vector<hpke::AeadId> supportedAeads);

hpke::SetupResult constructHpkeSetupResult(
    const fizz::Factory& factory,
    std::unique_ptr<KeyExchange> kex,
    const NegotiatedECHConfig& negotiatedECHConfig);

std::unique_ptr<folly::IOBuf> makeClientHelloAad(
    HpkeSymmetricCipherSuite cipherSuite,
    const uint8_t configId,
    const std::unique_ptr<folly::IOBuf>& enc,
    const std::unique_ptr<folly::IOBuf>& clientHello);

folly::Optional<ClientPresharedKey> generateGreasePSK(
    const ClientHello& chloInner,
    const Factory* factory);

ClientPresharedKey generateGreasePSKForHRR(
    const ClientPresharedKey& previousPsk,
    const Factory* factory);

ServerHello makeDummyServerHello(const ServerHello& shlo);

HelloRetryRequest makeDummyHRR(const HelloRetryRequest& hrr);

bool checkECHAccepted(
    const ServerHello& shlo,
    std::unique_ptr<HandshakeContext> context,
    std::unique_ptr<KeyScheduler> scheduler);

bool checkECHAccepted(
    const HelloRetryRequest& shlo,
    std::unique_ptr<HandshakeContext> context,
    std::unique_ptr<KeyScheduler> scheduler);

void setAcceptConfirmation(
    ServerHello& shlo,
    std::unique_ptr<HandshakeContext> context,
    std::unique_ptr<KeyScheduler> scheduler);

void setAcceptConfirmation(
    HelloRetryRequest& hrr,
    std::unique_ptr<HandshakeContext> context,
    std::unique_ptr<KeyScheduler> scheduler);

size_t
calculateECHPadding(const ClientHello& chlo, size_t encodedSize, size_t maxLen);

std::vector<Extension> generateAndReplaceOuterExtensions(
    std::vector<Extension>&& chloInnerExt,
    const std::vector<ExtensionType>& outerExtensionTypes);

OuterECHClientHello encryptClientHelloHRR(
    const NegotiatedECHConfig& negotiatedECHConfig,
    const ClientHello& clientHelloInner,
    const ClientHello& clientHelloOuter,
    hpke::SetupResult& setupResult,
    const folly::Optional<ClientPresharedKey>& greasePsk,
    const std::vector<ExtensionType>& outerExtensionTypes);

OuterECHClientHello encryptClientHello(
    const NegotiatedECHConfig& negotiatedECHConfig,
    const ClientHello& clientHelloInner,
    const ClientHello& clientHelloOuter,
    hpke::SetupResult& setupResult,
    const folly::Optional<ClientPresharedKey>& greasePsk,
    const std::vector<ExtensionType>& outerExtensionTypes);

ClientHello decryptECHWithContext(
    const ClientHello& clientHelloOuter,
    const ParsedECHConfig& echConfig,
    HpkeSymmetricCipherSuite& cipherSuite,
    std::unique_ptr<folly::IOBuf> encapsulatedKey,
    uint8_t configId,
    std::unique_ptr<folly::IOBuf> encryptedCh,
    ECHVersion version,
    std::unique_ptr<hpke::HpkeContext>& context);

std::unique_ptr<hpke::HpkeContext> setupDecryptionContext(
    const fizz::Factory& factory,
    const ParsedECHConfig& echConfig,
    HpkeSymmetricCipherSuite cipherSuite,
    const std::unique_ptr<folly::IOBuf>& encapsulatedKey,
    std::unique_ptr<KeyExchange> kex,
    uint64_t seqNum);

std::vector<Extension> substituteOuterExtensions(
    std::vector<Extension>&& innerExt,
    const std::vector<Extension>& outerExt);

} // namespace ech
} // namespace fizz
