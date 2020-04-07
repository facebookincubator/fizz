/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <map>
#include <unordered_map>

#include <fizz/protocol/Certificate.h>

namespace fizz {
namespace server {

class CertManager {
 public:
  using CertMatch =
      folly::Optional<std::pair<std::shared_ptr<SelfCert>, SignatureScheme>>;

  virtual ~CertManager() = default;

  /**
   * Select a cert given a client supplied SNI value, server
   * supportedSigSchemes, client peerSigSchemes, and client peerExtensions
   *
   * Will ignore peerSigSchemes if no matching certificate is found.
   */
  virtual CertMatch getCert(
      const folly::Optional<std::string>& sni,
      const std::vector<SignatureScheme>& supportedSigSchemes,
      const std::vector<SignatureScheme>& peerSigSchemes,
      const std::vector<Extension>& peerExtensions) const;

  /**
   * Return a certificate with the a primary identity exactly matching identity.
   * Will return nullptr if no matching cert is found.
   */
  virtual std::shared_ptr<SelfCert> getCert(const std::string& identity) const;

  void addCert(std::shared_ptr<SelfCert> cert, bool defaultCert = false);

 private:
  CertMatch findCert(
      const std::string& key,
      const std::vector<SignatureScheme>& supportedSigSchemes,
      const std::vector<SignatureScheme>& peerSigSchemes,
      CertMatch& lastResort) const;

  void addCertIdentity(
      std::shared_ptr<SelfCert> cert,
      const std::string& ident);

  using SigSchemeMap = std::map<SignatureScheme, std::shared_ptr<SelfCert>>;
  std::unordered_map<std::string, SigSchemeMap> certs_;
  std::unordered_map<std::string, std::shared_ptr<SelfCert>> identMap_;
  std::string default_;
};
} // namespace server
} // namespace fizz
