/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/extensions/ech/Encryption.h>

#include <fizz/extensions/ech/Types.h>

namespace fizz {
namespace extensions {

folly::Optional<SupportedECHConfig> selectECHConfig(std::vector<ECHConfigContentDraft7> configs,
  std::vector<hpke::KEMId> supportedKEMs, std::vector<hpke::KDFId>  supportedHashFunctions,
  std::vector<hpke::AeadId>  supportedCiphers) {

  // Received set of configs is in order of server preference so
  // we should be selecting the first one that we can support.
  for (auto& config : configs) {
    // Check if we (client) support the server's chosen KEM.
    auto result = std::find(supportedKEMs.begin(), supportedKEMs.end(), config.kem_id);
    if (result == supportedKEMs.end()) {
      continue;
    }

    // Check if we (client) support the HPKE cipher suite.
    auto cipherSuites = config.cipher_suites;
    for (auto &suite : cipherSuites) {
      auto isKdfSupported = std::find(supportedHashFunctions.begin(), supportedHashFunctions.end(), suite.kdfId) != supportedHashFunctions.end();
      auto isCipherSupported = std::find(supportedCiphers.begin(), supportedCiphers.end(), suite.aeadId) != supportedCiphers.end();

      if (isKdfSupported && isCipherSupported) {
        return SupportedECHConfig{std::move(config), suite};
      }
    }
  }
  return folly::none;
}

} // namespace extensions
} // namespace fizz
