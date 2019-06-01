/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/client/PskCache.h>
#include <fizz/protocol/CertDecompressionManager.h>
#include <fizz/protocol/Certificate.h>
#include <fizz/protocol/Factory.h>
#include <fizz/protocol/OpenSSLFactory.h>
#include <fizz/record/Types.h>

namespace fizz {
namespace client {

class FizzClientContext {
 public:
  FizzClientContext() : factory_(std::make_shared<OpenSSLFactory>()) {}
  FizzClientContext(std::shared_ptr<Factory> factory)
      : factory_(std::move(factory)) {}
  virtual ~FizzClientContext() = default;

  /**
   * Set the supported protocol versions, in preference order.
   */
  void setSupportedVersions(std::vector<ProtocolVersion> versions) {
    supportedVersions_ = std::move(versions);
  }

  const auto& getSupportedVersions() const {
    return supportedVersions_;
  }

  /**
   * Set the supported ciphers, in preference order.
   */
  void setSupportedCiphers(std::vector<CipherSuite> ciphers) {
    supportedCiphers_ = std::move(ciphers);
  }

  const auto& getSupportedCiphers() const {
    return supportedCiphers_;
  }

  /**
   * Set the supported signature schemes, in preference order.
   */
  void setSupportedSigSchemes(std::vector<SignatureScheme> schemes) {
    supportedSigSchemes_ = std::move(schemes);
  }

  const auto& getSupportedSigSchemes() const {
    return supportedSigSchemes_;
  }

  /**
   * Set the supported named groups, in preference order.
   */
  void setSupportedGroups(std::vector<NamedGroup> groups) {
    supportedGroups_ = std::move(groups);
  }

  const auto& getSupportedGroups() const {
    return supportedGroups_;
  }

  /**
   * Set the default key shares to send. Must be a subset of supported groups.
   */
  void setDefaultShares(std::vector<NamedGroup> groups) {
    defaultShares_ = std::move(groups);
  }
  const auto& getDefaultShares() const {
    return defaultShares_;
  }

  /**
   * Set the supported psk modes, in preference order.
   */
  void setSupportedPskModes(std::vector<PskKeyExchangeMode> modes) {
    supportedPskModes_ = std::move(modes);
  }

  const auto& getSupportedPskModes() const {
    return supportedPskModes_;
  }

  /**
   * Sets the supported ALPN supported protocols, in preference order.
   */
  void setSupportedAlpns(std::vector<std::string> protocols) {
    supportedAlpns_ = std::move(protocols);
  }

  const auto& getSupportedAlpns() const {
    return supportedAlpns_;
  }

  /**
   * Sets the certificate to use if the server requests client authentication
   */
  void setClientCertificate(std::shared_ptr<SelfCert> cert) {
    clientCert_ = std::move(cert);
  }

  const auto& getClientCertificate() const {
    return clientCert_;
  }

  /**
   * Set the Psk Cache to use.
   */
  void setPskCache(std::shared_ptr<PskCache> pskCache) {
    pskCache_ = std::move(pskCache);
  }

  folly::Optional<CachedPsk> getPsk(const std::string& identity) const {
    if (pskCache_) {
      return pskCache_->getPsk(identity);
    } else {
      return folly::none;
    }
  }

  void putPsk(const std::string& identity, CachedPsk psk) const {
    if (pskCache_) {
      pskCache_->putPsk(identity, std::move(psk));
    }
  }

  void removePsk(const std::string& identity) const {
    if (pskCache_) {
      pskCache_->removePsk(identity);
    }
  }

  /**
   * Sets whether we should attempt to send early data.
   */
  void setSendEarlyData(bool sendEarlyData) {
    sendEarlyData_ = sendEarlyData;
  }

  bool getSendEarlyData() const {
    return sendEarlyData_;
  }

  /**
   * Sets whether we want to use compatibility mode (sending a fake session ID
   * and ChangeCipherSpec).
   */
  void setCompatibilityMode(bool enabled) {
    compatMode_ = enabled;
  }

  bool getCompatibilityMode() const {
    return compatMode_;
  }

  /**
   * Set the factory to use. Should generally only be changed for testing.
   */
  void setFactory(std::shared_ptr<Factory> factory) {
    factory_ = std::move(factory);
  }

  const Factory* getFactory() const {
    return factory_.get();
  }

  /**
   * Sets the certificate decompression manager for server certs.
   */
  void setCertDecompressionManager(
      std::shared_ptr<CertDecompressionManager> mgr) {
    certDecompressionManager_ = mgr;
  }

  /**
   * Returns a vector representing the compression algorithms the manager has
   * decompressors for.
   */
  std::vector<CertificateCompressionAlgorithm>
  getSupportedCertDecompressionAlgorithms() const {
    if (certDecompressionManager_) {
      return certDecompressionManager_->getSupportedAlgorithms();
    } else {
      return {};
    }
  }

  /**
   * Given a compression algorithm, returns the decompressor to decompress
   * certs. If the algorithm isn't found, returns nullptr.
   */
  std::shared_ptr<CertificateDecompressor> getCertDecompressorForAlgorithm(
      CertificateCompressionAlgorithm algo) const {
    if (certDecompressionManager_) {
      return certDecompressionManager_->getDecompressor(algo);
    } else {
      return nullptr;
    }
  }

  /**
   * Whether to omit the early record layer when sending early data. This will
   * also omit the EndOfEarlyData message.
   * Default is false, and using this requires a custom record layer.
   */
  void setOmitEarlyRecordLayer(bool enabled) {
    omitEarlyRecordLayer_ = enabled;
  }
  bool getOmitEarlyRecordLayer() const {
    return omitEarlyRecordLayer_;
  }

 private:
  std::shared_ptr<Factory> factory_;

  std::vector<ProtocolVersion> supportedVersions_ = {ProtocolVersion::tls_1_3};
  std::vector<CipherSuite> supportedCiphers_ = {
      CipherSuite::TLS_AES_128_GCM_SHA256,
      CipherSuite::TLS_AES_256_GCM_SHA384,
#if FOLLY_OPENSSL_HAS_CHACHA
      CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
#endif // FOLLY_OPENSSL_HAS_CHACHA
  };
  std::vector<SignatureScheme> supportedSigSchemes_ = {
      SignatureScheme::ecdsa_secp256r1_sha256,
      SignatureScheme::rsa_pss_sha256};
  std::vector<NamedGroup> supportedGroups_ = {NamedGroup::x25519,
                                              NamedGroup::secp256r1};
  std::vector<NamedGroup> defaultShares_ = {NamedGroup::x25519};
  std::vector<PskKeyExchangeMode> supportedPskModes_ = {
      PskKeyExchangeMode::psk_dhe_ke,
      PskKeyExchangeMode::psk_ke};
  std::vector<std::string> supportedAlpns_;
  bool sendEarlyData_{false};

  bool compatMode_{false};

  bool omitEarlyRecordLayer_{false};

  std::shared_ptr<PskCache> pskCache_;
  std::shared_ptr<const SelfCert> clientCert_;
  std::shared_ptr<CertDecompressionManager> certDecompressionManager_;
};
} // namespace client
} // namespace fizz
