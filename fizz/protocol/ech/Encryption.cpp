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
#include <fizz/crypto/hpke/Utils.h>
#include <fizz/protocol/ech/ECHExtensions.h>
#include <fizz/protocol/ech/Types.h>

namespace fizz {
namespace ech {

namespace {

std::unique_ptr<folly::IOBuf> makeClientHelloOuterAad(
    const ClientHello& clientHelloOuter) {
  // Copy client hello outer
  ClientHello chloCopy = clientHelloOuter.clone();

  // Remove ech extension from the copy
  auto it =
      findExtension(chloCopy.extensions, ExtensionType::encrypted_client_hello);
  chloCopy.extensions.erase(it);

  // Get the serialized version of the client hello outer
  // without the ECH extension to use
  auto clientHelloOuterAad = encode(chloCopy);
  return clientHelloOuterAad;
}

std::unique_ptr<folly::IOBuf> extractEncodedClientHelloInner(
    ECHVersion version,
    std::unique_ptr<folly::IOBuf> encryptedCh,
    hpke::HpkeContext& context,
    const ClientHello& clientHelloOuter) {
  std::unique_ptr<folly::IOBuf> encodedClientHelloInner;
  switch (version) {
    case ECHVersion::V7: {
      encodedClientHelloInner = context.open(
          folly::IOBuf::copyBuffer("").get(), std::move(encryptedCh));
      break;
    }
    case ECHVersion::V8: {
      auto chloOuterAad = makeClientHelloOuterAad(clientHelloOuter);
      encodedClientHelloInner =
          context.open(chloOuterAad.get(), std::move(encryptedCh));
      break;
    }
  }
  return encodedClientHelloInner;
}

std::unique_ptr<folly::IOBuf> makeHpkeContextInfoParam(
    const ECHConfig& echConfig) {
  switch (echConfig.version) {
    case ECHVersion::V7:
      return folly::IOBuf::copyBuffer("tls13-ech");
    case ECHVersion::V8: {
      // The "info" parameter to setupWithEncap is the
      // concatenation of "tls ech", a zero byte, and the serialized
      // ECHConfig.
      std::string tlsEchPrefix = "tls ech";
      tlsEchPrefix += '\0';
      auto bufContents = folly::IOBuf::copyBuffer(tlsEchPrefix);
      bufContents->prependChain(encode(echConfig));

      return bufContents;
    }
  }
  return nullptr;
}

bool isNonceValueEqual(
    const hpke::HpkeContext& context,
    const ClientHello& decodedChlo) {
  std::unique_ptr<folly::IOBuf> expectedNonceValue =
      context.exportSecret(folly::IOBuf::copyBuffer("tls13-ech-nonce"), 16);
  auto it = findExtension(decodedChlo.extensions, ExtensionType::ech_nonce);
  if (it == decodedChlo.extensions.end()) {
    return false;
  }
  folly::io::Cursor cs{it->extension_data.get()};
  auto gotEchNonceExtension = getExtension<ech::ECHNonce>(cs);

  auto gotNonceValue = folly::IOBuf::copyBuffer(gotEchNonceExtension.nonce);
  if (!folly::IOBufEqualTo()(gotNonceValue, expectedNonceValue)) {
    return false;
  }

  return true;
}

} // namespace

std::unique_ptr<folly::IOBuf> constructConfigId(
    hpke::KDFId kdfId,
    ECHConfig echConfig) {
  std::unique_ptr<HkdfImpl> hkdf;
  size_t hashLen;
  switch (kdfId) {
    case (hpke::KDFId::Sha256): {
      hkdf = std::make_unique<HkdfImpl>(HkdfImpl::create<Sha256>());
      hashLen = Sha256::HashLen;
      break;
    }
    case (hpke::KDFId::Sha384): {
      hkdf = std::make_unique<HkdfImpl>(HkdfImpl::create<Sha384>());
      hashLen = Sha384::HashLen;
      break;
    }
    default: {
      throw std::runtime_error("kdf: not implemented");
    }
  }

  auto extractedChlo = hkdf->extract(
      folly::IOBuf::copyBuffer("")->coalesce(),
      encode(std::move(echConfig))->coalesce());
  return hkdf->expand(
      extractedChlo, *folly::IOBuf::copyBuffer("tls ech config id"), hashLen);
}

folly::Optional<SupportedECHConfig> selectECHConfig(
    const std::vector<ECHConfig>& configs,
    std::vector<hpke::KEMId> supportedKEMs,
    std::vector<hpke::AeadId> supportedAeads) {
  // Received set of configs is in order of server preference so
  // we should be selecting the first one that we can support.
  for (const auto& config : configs) {
    folly::io::Cursor cursor(config.ech_config_content.get());
    if (config.version == ECHVersion::V7 || config.version == ECHVersion::V8) {
      auto echConfig = decode<ECHConfigContentDraft>(cursor);
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
                supportedAeads.begin(), supportedAeads.end(), suite.aead_id) !=
            supportedAeads.end();
        if (isCipherSupported) {
          auto associatedCipherKdf =
              hpke::getKDFId(getHashFunction(getCipherSuite(suite.aead_id)));
          if (suite.kdf_id == associatedCipherKdf) {
            auto supportedConfig = config;
            return SupportedECHConfig{supportedConfig, suite};
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
    const ECHCipherSuite& cipherSuite) {
  // Get suite id
  auto group = getKexGroup(kemId);
  auto hash = getHashFunction(cipherSuite.kdf_id);
  auto suite = getCipherSuite(cipherSuite.aead_id);
  auto suiteId = hpke::generateHpkeSuiteId(group, hash, suite);

  auto hkdf = hpke::makeHpkeHkdf(std::move(prefix), cipherSuite.kdf_id);

  return hpke::SetupParam{
      std::move(dhkem),
      makeCipher(cipherSuite.aead_id),
      std::move(hkdf),
      std::move(suiteId)};
}

std::unique_ptr<folly::IOBuf> getRecordDigest(
    const ECHConfig& echConfig,
    hpke::KDFId id) {
  switch (id) {
    case hpke::KDFId::Sha256: {
      std::array<uint8_t, fizz::Sha256::HashLen> recordDigest;
      fizz::Sha256::hash(
          *encode(echConfig),
          folly::MutableByteRange(recordDigest.data(), recordDigest.size()));
      return folly::IOBuf::copyBuffer(recordDigest);
    }
    case hpke::KDFId::Sha384: {
      std::array<uint8_t, fizz::Sha384::HashLen> recordDigest;
      fizz::Sha384::hash(
          *encode(echConfig),
          folly::MutableByteRange(recordDigest.data(), recordDigest.size()));
      return folly::IOBuf::copyBuffer(recordDigest);
    }
    default:
      throw std::runtime_error("kdf: not implemented");
  }
}

ech::ECHNonce createNonceExtension(const hpke::HpkeContext& context) {
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

  if (supportedConfig.config.version != ECHVersion::V7 &&
      supportedConfig.config.version != ECHVersion::V8) {
    throw std::runtime_error("encrypt client hello: version not implemented");
  }

  folly::io::Cursor cursor(supportedConfig.config.ech_config_content.get());
  auto config = decode<ECHConfigContentDraft>(cursor);
  auto cipherSuite = supportedConfig.cipherSuite;

  // Get shared secret
  auto hkdf = hpke::makeHpkeHkdf(prefix->clone(), cipherSuite.kdf_id);
  std::unique_ptr<DHKEM> dhkem = std::make_unique<DHKEM>(
      std::move(kex), getKexGroup(config.kem_id), std::move(hkdf));

  // Get context
  std::unique_ptr<folly::IOBuf> info =
      makeHpkeContextInfoParam(supportedConfig.config);

  return setupWithEncap(
      hpke::Mode::Base,
      config.public_key->clone()->coalesce(),
      std::move(info),
      folly::none,
      getSetupParam(
          std::move(dhkem), prefix->clone(), config.kem_id, cipherSuite));
}

ClientECH encryptClientHelloV8(
    const SupportedECHConfig& supportedConfig,
    const ClientHello& clientHelloInner,
    const ClientHello& clientHelloOuter,
    hpke::SetupResult setupResult) {
  // Create ECH extension
  ClientECH echExtension;
  echExtension.cipher_suite = supportedConfig.cipherSuite;
  echExtension.config_id = constructConfigId(
      supportedConfig.cipherSuite.kdf_id, supportedConfig.config);
  echExtension.enc = std::move(setupResult.enc);

  // Remove legacy_session_id and serialize the client hello inner
  auto chloInnerCopy = clientHelloInner.clone();
  chloInnerCopy.legacy_session_id = folly::IOBuf::copyBuffer("");
  auto encodedClientHelloInner = encode(chloInnerCopy);

  // Encrypt and serialize client hello inner
  auto clientHelloOuterAad = encode(clientHelloOuter);
  echExtension.payload = setupResult.context.seal(
      clientHelloOuterAad.get(), std::move(encodedClientHelloInner));
  return echExtension;
}

EncryptedClientHello encryptClientHello(
    const SupportedECHConfig& supportedConfig,
    ClientHello clientHello,
    hpke::SetupResult setupResult) {
  auto cipherSuite = supportedConfig.cipherSuite;
  folly::io::Cursor cursor(supportedConfig.config.ech_config_content.get());

  // Create client hello outer
  EncryptedClientHello clientHelloOuter;
  clientHelloOuter.suite = cipherSuite;

  // Hash the ECH config
  clientHelloOuter.record_digest =
      getRecordDigest(supportedConfig.config, cipherSuite.kdf_id);
  clientHelloOuter.enc = std::move(setupResult.enc);

  // Create client hello inner
  clientHelloOuter.encrypted_ch = setupResult.context.seal(
      folly::IOBuf::copyBuffer("").get(), encode(clientHello));

  return clientHelloOuter;
}

folly::Optional<ClientHello> tryToDecryptECH(
    const ClientHello& clientHelloOuter,
    const ECHConfig& echConfig,
    ECHCipherSuite cipherSuite,
    std::unique_ptr<folly::IOBuf> encapsulatedKey,
    std::unique_ptr<folly::IOBuf> encryptedCh,
    std::unique_ptr<KeyExchange> kex,
    ECHVersion version) {
  const std::unique_ptr<folly::IOBuf> prefix{
      folly::IOBuf::copyBuffer("HPKE-05 ")};

  // Get crypto primitive types used for decrypting
  hpke::KDFId kdfId = cipherSuite.kdf_id;
  folly::io::Cursor echConfigCursor(echConfig.ech_config_content.get());
  auto decodedConfigContent = decode<ECHConfigContentDraft>(echConfigCursor);
  auto kemId = decodedConfigContent.kem_id;
  NamedGroup group = hpke::getKexGroup(kemId);

  // Try to decrypt and get the client hello inner
  try {
    auto dhkem = std::make_unique<DHKEM>(
        std::move(kex), group, hpke::makeHpkeHkdf(prefix->clone(), kdfId));
    auto aeadId = cipherSuite.aead_id;
    auto suiteId = hpke::generateHpkeSuiteId(
        group, hpke::getHashFunction(kdfId), hpke::getCipherSuite(aeadId));

    hpke::SetupParam setupParam{
        std::move(dhkem),
        makeCipher(aeadId),
        hpke::makeHpkeHkdf(prefix->clone(), kdfId),
        std::move(suiteId)};

    std::unique_ptr<folly::IOBuf> info = makeHpkeContextInfoParam(echConfig);
    auto context = hpke::setupWithDecap(
        hpke::Mode::Base,
        encapsulatedKey->coalesce(),
        std::move(info),
        folly::none,
        std::move(setupParam));

    auto encodedClientHelloInner = extractEncodedClientHelloInner(
        version, std::move(encryptedCh), context, clientHelloOuter);

    // Set actual client hello, ECH acceptance
    folly::io::Cursor encodedECHInnerCursor(encodedClientHelloInner.get());
    auto decodedChlo = decode<ClientHello>(encodedECHInnerCursor);
    decodedChlo.originalEncoding = encodeHandshake(decodedChlo);

    if (version == ECHVersion::V8) {
      // Replace legacy_session_id that got removed during encryption
      decodedChlo.legacy_session_id =
          clientHelloOuter.legacy_session_id->clone();
    }

    // Check ECH nonce if V7
    if (version == ECHVersion::V7 && !isNonceValueEqual(context, decodedChlo)) {
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
