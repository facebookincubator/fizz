/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/protocol/ech/Encryption.h>
#include "fizz/record/Types.h"

#include <fizz/crypto/Sha256.h>
#include <fizz/crypto/Sha384.h>
#include <fizz/crypto/hpke/Utils.h>
#include <fizz/protocol/Protocol.h>
#include <fizz/protocol/ech/ECHExtensions.h>
#include <fizz/protocol/ech/Types.h>
#include <iterator>

namespace fizz {
namespace ech {

namespace {

std::unique_ptr<folly::IOBuf> makeClientHelloOuterForAad(
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
    std::unique_ptr<folly::IOBuf> configId,
    const ECHCipherSuite& cipherSuite,
    const std::unique_ptr<folly::IOBuf>& encapsulatedKey,
    std::unique_ptr<folly::IOBuf> encryptedCh,
    hpke::HpkeContext& context,
    const ClientHello& clientHelloOuter) {
  std::unique_ptr<folly::IOBuf> encodedClientHelloInner;
  switch (version) {
    case ECHVersion::Draft9: {
      auto aadCH = makeClientHelloOuterForAad(clientHelloOuter);
      auto chloOuterAad =
          makeClientHelloAad(cipherSuite, configId, encapsulatedKey, aadCH);
      encodedClientHelloInner =
          context.open(chloOuterAad.get(), std::move(encryptedCh));
    }
  }
  return encodedClientHelloInner;
}

std::unique_ptr<folly::IOBuf> makeHpkeContextInfoParam(
    const ECHConfig& echConfig) {
  switch (echConfig.version) {
    case ECHVersion::Draft9: {
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

} // namespace

std::unique_ptr<folly::IOBuf> constructConfigId(
    hpke::KDFId kdfId,
    ECHConfig echConfig) {
  std::unique_ptr<HkdfImpl> hkdf;
  // Draft 9 set this to a fixed value
  const size_t hashLen = 8;
  switch (kdfId) {
    case (hpke::KDFId::Sha256): {
      hkdf = std::make_unique<HkdfImpl>(HkdfImpl::create<Sha256>());
      break;
    }
    case (hpke::KDFId::Sha384): {
      hkdf = std::make_unique<HkdfImpl>(HkdfImpl::create<Sha384>());
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
    if (config.version == ECHVersion::Draft9) {
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

hpke::SetupResult constructHpkeSetupResult(
    std::unique_ptr<KeyExchange> kex,
    const SupportedECHConfig& supportedConfig) {
  const std::unique_ptr<folly::IOBuf> prefix =
      folly::IOBuf::copyBuffer("HPKE-07");

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

std::unique_ptr<folly::IOBuf> makeClientHelloAad(
    ECHCipherSuite cipherSuite,
    const std::unique_ptr<folly::IOBuf>& configId,
    const std::unique_ptr<folly::IOBuf>& enc,
    const std::unique_ptr<folly::IOBuf>& clientHello) {
  auto aad = folly::IOBuf::create(0);
  folly::io::Appender appender(aad.get(), 32);
  detail::write<ech::ECHCipherSuite>(cipherSuite, appender);
  detail::writeBuf<uint8_t>(configId, appender);
  detail::writeBuf<uint16_t>(enc, appender);
  detail::writeBuf<detail::bits24>(clientHello, appender);
  return aad;
}

ServerHello makeDummyServerHello(const ServerHello& shlo) {
  std::vector<Extension> extensionCopies;
  for (auto& ext : shlo.extensions) {
    extensionCopies.push_back(ext.clone());
  }
  ServerHello shloEch;
  shloEch.legacy_version = shlo.legacy_version;
  shloEch.random = shlo.random;
  shloEch.legacy_session_id_echo = shlo.legacy_session_id_echo->clone();
  shloEch.cipher_suite = shlo.cipher_suite;
  shloEch.legacy_compression_method = shlo.legacy_compression_method;
  shloEch.extensions = std::move(extensionCopies);
  // Zero the acceptance confirmation bytes
  memset(
      shloEch.random.data() +
          (shloEch.random.size() - kEchAcceptConfirmationSize),
      0,
      kEchAcceptConfirmationSize);
  return shloEch;
}

namespace {

std::vector<uint8_t> calculateAcceptConfirmation(
    const ServerHello& shlo,
    std::unique_ptr<HandshakeContext> context,
    std::unique_ptr<KeyScheduler>& scheduler) {
  // Acceptance is done by feeding a dummy hello into the transcript and
  // deriving a secret from it.
  auto shloEch = makeDummyServerHello(shlo);
  context->appendToTranscript(encodeHandshake(std::move(shloEch)));

  auto hsc = context->getHandshakeContext();
  auto echAcceptance = scheduler->getSecret(
      HandshakeSecrets::ECHAcceptConfirmation, hsc->coalesce());

  return std::move(echAcceptance.secret);
}

} // namespace

bool checkECHAccepted(
    const ServerHello& shlo,
    std::unique_ptr<HandshakeContext> context,
    std::unique_ptr<KeyScheduler>& scheduler) {
  auto acceptConfirmation =
      calculateAcceptConfirmation(shlo, std::move(context), scheduler);
  // ECH accepted if the 8 bytes match the accept_confirmation
  return memcmp(
             shlo.random.data() +
                 (shlo.random.size() - kEchAcceptConfirmationSize),
             acceptConfirmation.data(),
             kEchAcceptConfirmationSize) == 0;
}

void setAcceptConfirmation(
    ServerHello& shlo,
    std::unique_ptr<HandshakeContext> context,
    std::unique_ptr<KeyScheduler>& scheduler) {
  auto acceptConfirmation =
      calculateAcceptConfirmation(shlo, std::move(context), scheduler);

  // Copy the acceptance confirmation bytes to the end
  memcpy(
      shlo.random.data() + (shlo.random.size() - kEchAcceptConfirmationSize),
      acceptConfirmation.data(),
      kEchAcceptConfirmationSize);
}

ClientECH encryptClientHello(
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

  // Compute the AAD for sealing
  auto clientHelloOuterEnc = encode(clientHelloOuter);
  auto clientHelloOuterAad = makeClientHelloAad(
      supportedConfig.cipherSuite,
      echExtension.config_id,
      echExtension.enc,
      clientHelloOuterEnc);

  // Encrypt inner client hello
  echExtension.payload = setupResult.context.seal(
      clientHelloOuterAad.get(), std::move(encodedClientHelloInner));
  return echExtension;
}

folly::Optional<ClientHello> tryToDecryptECH(
    const ClientHello& clientHelloOuter,
    const ECHConfig& echConfig,
    ECHCipherSuite cipherSuite,
    std::unique_ptr<folly::IOBuf> encapsulatedKey,
    std::unique_ptr<folly::IOBuf> encryptedCh,
    std::unique_ptr<KeyExchange> kex,
    ECHVersion version) {
  const std::unique_ptr<folly::IOBuf> prefix =
      folly::IOBuf::copyBuffer("HPKE-07");

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
        version,
        constructConfigId(cipherSuite.kdf_id, echConfig),
        cipherSuite,
        encapsulatedKey,
        std::move(encryptedCh),
        context,
        clientHelloOuter);

    // Set actual client hello, ECH acceptance
    folly::io::Cursor encodedECHInnerCursor(encodedClientHelloInner.get());
    auto decodedChlo = decode<ClientHello>(encodedECHInnerCursor);
    decodedChlo.originalEncoding = encodeHandshake(decodedChlo);

    // Replace legacy_session_id that got removed during encryption
    decodedChlo.legacy_session_id = clientHelloOuter.legacy_session_id->clone();

    // TODO: Scan for outer_extensions extension.
    return decodedChlo;
  } catch (const std::exception&) {
  }

  return folly::none;
}

std::vector<Extension> substituteOuterExtensions(
    std::vector<Extension>&& innerExt,
    const std::vector<Extension>& outerExt) {
  std::vector<Extension> expandedInnerExt;

  // validate that the innerExt has no duplicate extensions.
  Protocol::checkDuplicateExtensions(innerExt);

  // locate echOuterExtension
  auto echOuterExtension = std::find_if(
      innerExt.cbegin(), innerExt.cend(), [](const Extension& ext) {
        return ext.extension_type == fizz::ExtensionType::ech_outer_extensions;
      });

  // Return innerExt if no ech_outer_extensions extension was found.
  if (echOuterExtension == innerExt.end()) {
    return std::move(innerExt);
  }

  folly::io::Cursor cursor(echOuterExtension->extension_data.get());

  std::vector<ExtensionType> outerExtsToCopy;
  fizz::detail::readVector<std::uint8_t>(outerExtsToCopy, cursor);

  // Insert all innerExt extensions before ech_outer_extensions.
  std::transform(
      innerExt.cbegin(),
      echOuterExtension,
      std::back_inserter(expandedInnerExt),
      [](const Extension& ext) { return ext.clone(); });

  /**
   * Expand ech_outer_extensions using the following two pointer approach:
   * Iterate over the outerExt and when both pointers have
   * equivalent extensions types, we increment idxInner
   * –indicating that we've validated an extension is present in
   * outerExt and maintains its relative ordering.
   */
  std::size_t idxInner = 0;

  for (const auto& ext : outerExt) {
    if (idxInner >= outerExtsToCopy.size()) {
      break;
    }

    if ((ext.extension_type == outerExtsToCopy[idxInner])) {
      expandedInnerExt.push_back(ext.clone());
      idxInner++;
    }
  }

  /**
   * If we've reached the end of the outerExtensionPtrs, the following
   * requirements have been satisfied:
   *
   * 1. All extensions in outerExtension are present in clientOuterHello
   * 2. The extensions in outerExtension preserve the relative ordering of
   * extensions in clientOuterHello.
   *
   * Otherwise we've violated one of the requirements.
   **/
  if (idxInner < outerExtsToCopy.size()) {
    throw fizz::FizzException(
        "Requirements for OuterExtensions not met.",
        AlertDescription::decode_error);
  }

  // Add all extensions that follow the ech_outer_extensions; resulting vector
  // is the list of substituted extensions
  std::transform(
      std::next(echOuterExtension, 1),
      innerExt.cend(),
      std::back_inserter(expandedInnerExt),
      [](const Extension& ext) { return ext.clone(); });

  // Verify that there are no duplicate extensions.
  std::unordered_set<ExtensionType> expandedExtTypes;

  std::transform(
      expandedInnerExt.cbegin(),
      expandedInnerExt.cend(),
      std::inserter(expandedExtTypes, expandedExtTypes.begin()),
      [](const Extension& ext) { return ext.extension_type; });

  if (expandedExtTypes.size() != expandedInnerExt.size()) {
    throw FizzException(
        "Duplicate extensions", AlertDescription::illegal_parameter);
  }

  return expandedInnerExt;
}

} // namespace ech
} // namespace fizz
