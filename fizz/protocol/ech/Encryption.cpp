/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/protocol/ech/Encryption.h>

#include <fizz/crypto/Sha256.h>
#include <fizz/crypto/Sha384.h>
#include <fizz/protocol/ech/ECHExtensions.h>
#include <fizz/protocol/ech/Types.h>
#include <fizz/crypto/hpke/Utils.h>

namespace fizz {
namespace ech {

folly::Optional<SupportedECHConfig> selectECHConfig(
    const std::vector<ECHConfig>& configs,
    std::vector<hpke::KEMId> supportedKEMs,
    std::vector<hpke::AeadId> supportedAeads) {
  // Received set of configs is in order of server preference so
  // we should be selecting the first one that we can support.
  for (const auto& config : configs) {
    folly::io::Cursor cursor(config.ech_config_content.get());
    if (config.version == ECHVersion::V7) {
      auto echConfig = decode<ECHConfigContentDraft7>(cursor);
      // Check if we (client) support the server's chosen KEM.
      auto result = std::find(
          supportedKEMs.begin(), supportedKEMs.end(), echConfig.kem_id);
      if (result == supportedKEMs.end()) {
        continue;
      }

      // Check if we (client) support the HPKE cipher suite.
      auto cipherSuites = echConfig.cipher_suites;
      for (auto& suite : cipherSuites) {
        auto isCipherSupported =
            std::find(
                supportedAeads.begin(), supportedAeads.end(), suite.aeadId) !=
            supportedAeads.end();
        if (isCipherSupported) {
          auto associatedCipherKdf =
              hpke::getKDFId(getHashFunction(getCipherSuite(suite.aeadId)));
          if (suite.kdfId == associatedCipherKdf) {
            return SupportedECHConfig{config.clone(), suite};
          }
        }
      }
    }
  }
  return folly::none;
}

static hpke::SetupParam getSetupParam(
    std::unique_ptr<DHKEM> dhkem,
    std::unique_ptr<folly::IOBuf> prefix,
    hpke::KEMId kemId,
    const HpkeCipherSuite& cipherSuite) {
  // Get suite id
  auto group = getKexGroup(kemId);
  auto hash = getHashFunction(cipherSuite.kdfId);
  auto suite = getCipherSuite(cipherSuite.aeadId);
  auto suiteId = hpke::generateHpkeSuiteId(group, hash, suite);

  auto hkdf = hpke::makeHpkeHkdf(std::move(prefix), cipherSuite.kdfId);

  return hpke::SetupParam{std::move(dhkem),
                          makeCipher(cipherSuite.aeadId),
                          std::move(hkdf),
                          std::move(suiteId)};
}

static std::unique_ptr<folly::IOBuf> getRecordDigest(
    std::unique_ptr<folly::IOBuf> echConfig,
    hpke::KDFId id) {
  switch (id) {
    case hpke::KDFId::Sha256: {
      std::array<uint8_t, fizz::Sha256::HashLen> recordDigest;
      fizz::Sha256::hash(
          *echConfig,
          folly::MutableByteRange(recordDigest.data(), recordDigest.size()));
      return folly::IOBuf::copyBuffer(recordDigest);
    }
    case hpke::KDFId::Sha384: {
      std::array<uint8_t, fizz::Sha384::HashLen> recordDigest;
      fizz::Sha384::hash(
          *echConfig,
          folly::MutableByteRange(recordDigest.data(), recordDigest.size()));
      return folly::IOBuf::copyBuffer(recordDigest);
    }
    default:
      throw std::runtime_error("kdf: not implemented");
  }
}

ech::ECHNonce createNonceExtension(
    const hpke::HpkeContext& context) {
  std::array<uint8_t, 16> nonceValueArr;

  // Generate nonce value
  std::unique_ptr<folly::IOBuf> echNonceValue =
      context.exportSecret(folly::IOBuf::copyBuffer("tls13-ech-nonce"), 16);

  auto nonceValueRange = echNonceValue->coalesce();
  std::copy(
      nonceValueRange.begin(),
      nonceValueRange.begin() + 16,
      nonceValueArr.begin());

  return ECHNonce{nonceValueArr};
}

hpke::SetupResult constructHpkeSetupResult(
    std::unique_ptr<KeyExchange> kex,
    const SupportedECHConfig& supportedConfig) {
  const std::unique_ptr<folly::IOBuf> prefix{
      folly::IOBuf::copyBuffer("HPKE-05 ")};

  if (supportedConfig.config.version != ECHVersion::V7) {
    throw std::runtime_error("encrypt client hello: version not implemented");
  }

  folly::io::Cursor cursor(supportedConfig.config.ech_config_content.get());
  auto config = decode<ECHConfigContentDraft7>(cursor);
  auto cipherSuite = supportedConfig.cipherSuite;

  // Get shared secret
  auto hkdf = hpke::makeHpkeHkdf(prefix->clone(), cipherSuite.kdfId);
  std::unique_ptr<DHKEM> dhkem = std::make_unique<DHKEM>(
      std::move(kex), getKexGroup(config.kem_id), std::move(hkdf));

  // Get context
  return setupWithEncap(
      hpke::Mode::Base,
      config.public_key->clone()->coalesce(),
      folly::IOBuf::copyBuffer("tls13-ech"),
      folly::none,
      getSetupParam(
          std::move(dhkem), prefix->clone(), config.kem_id, cipherSuite));
}

EncryptedClientHello encryptClientHello(
    const SupportedECHConfig& supportedConfig,
    ClientHello clientHello,
    hpke::SetupResult setupResult) {
  auto context = std::move(setupResult.context);
  auto cipherSuite = supportedConfig.cipherSuite;
  folly::io::Cursor cursor(supportedConfig.config.ech_config_content.get());
  auto config = decode<ECHConfigContentDraft7>(cursor);

  // Create client hello inner
  std::unique_ptr<folly::IOBuf> clientHelloInner = encode(clientHello);
  std::unique_ptr<folly::IOBuf> encryptedCh = context.seal(
      folly::IOBuf::copyBuffer("").get(), clientHelloInner->clone());

  // Create client hello outer
  EncryptedClientHello clientHelloOuter;
  clientHelloOuter.suite = cipherSuite;

  // Hash the ECH config
  clientHelloOuter.record_digest =
      getRecordDigest(encode(std::move(config)), cipherSuite.kdfId);
  clientHelloOuter.enc = std::move(setupResult.enc);
  clientHelloOuter.encrypted_ch = std::move(encryptedCh);

  return clientHelloOuter;
}

folly::Optional<ClientHello> tryToDecryptECH(
    const Factory& factory,
    NamedGroup group,
    const ech::EncryptedClientHello& echExtension,
    std::unique_ptr<KeyExchange> kex) {
  const std::unique_ptr<folly::IOBuf> prefix{
      folly::IOBuf::copyBuffer("HPKE-05 ")};

  hpke::KDFId kdfId = echExtension.suite.kdfId;

  // Try to decrypt and get the client hello inner
  try {
    auto dhkem = std::make_unique<DHKEM>(
        std::move(kex),
        group,
        hpke::makeHpkeHkdf(prefix->clone(), kdfId));
    auto aeadId = echExtension.suite.aeadId;
    auto suiteId = hpke::generateHpkeSuiteId(
        group, hpke::getHashFunction(kdfId), hpke::getCipherSuite(aeadId));

    hpke::SetupParam setupParam{
        std::move(dhkem),
        factory.makeAead(hpke::getCipherSuite(aeadId)),
        hpke::makeHpkeHkdf(prefix->clone(), kdfId),
        std::move(suiteId)};

    auto context = hpke::setupWithDecap(
        hpke::Mode::Base,
        echExtension.enc->clone()->coalesce(),
        folly::IOBuf::copyBuffer("tls13-ech"),
        folly::none,
        std::move(setupParam));

    auto encodedClientHelloInner = context.open(
        folly::IOBuf::copyBuffer("").get(), echExtension.encrypted_ch->clone());

    // Set actual client hello, ECH acceptance
    folly::io::Cursor encodedECHInnerCursor(encodedClientHelloInner.get());
    auto decodedChlo = decode<ClientHello>(encodedECHInnerCursor);
    decodedChlo.originalEncoding = encodeHandshake(decodedChlo);

    // Check ECH nonce
    std::unique_ptr<folly::IOBuf> expectedNonceValue =
      context.exportSecret(folly::IOBuf::copyBuffer("tls13-ech-nonce"), 16);
    auto it = findExtension(decodedChlo.extensions, ExtensionType::ech_nonce);
    if (it == decodedChlo.extensions.end()) {
      return folly::none;
    }
    folly::io::Cursor cs{it->extension_data.get()};
    auto gotEchNonceExtension = getExtension<ech::ECHNonce>(cs);

    auto gotNonceValue = folly::IOBuf::copyBuffer(gotEchNonceExtension.nonce);
    if (!folly::IOBufEqualTo()(gotNonceValue, expectedNonceValue)) {
      return folly::none;
    }

    // TODO: Scan for outer_extensions extension.
    return decodedChlo;
  } catch (const std::exception&) {
  }

  return folly::none;
}

} // namespace ech
} // namespace fizz
