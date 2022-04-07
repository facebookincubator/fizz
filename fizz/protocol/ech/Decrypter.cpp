/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/protocol/ech/Decrypter.h>

namespace fizz {
namespace ech {

namespace {

folly::Optional<ClientHello> tryToDecodeECH(
    const ClientHello& clientHelloOuter,
    const Extension& encodedECHExtension,
    const std::vector<DecrypterParams>& decrypterParams) {
  for (const auto& param : decrypterParams) {
    folly::io::Cursor cursor(encodedECHExtension.extension_data.get());
    folly::Optional<ClientHello> decryptionResult;
    switch (param.echConfig.version) {
      case ECHVersion::Draft9: {
        auto echExtension = getExtension<ech::ClientECH>(cursor);
        auto echConfig = param.echConfig;
        const auto& currentConfigId =
            constructConfigId(echExtension.cipher_suite.kdf_id, echConfig);
        if (!folly::IOBufEqualTo()(currentConfigId, echExtension.config_id)) {
          continue;
        }

        // Decrypt client hello
        decryptionResult = tryToDecryptECH(
            clientHelloOuter,
            param.echConfig,
            echExtension.cipher_suite,
            echExtension.enc->clone(),
            echExtension.payload->clone(),
            param.kex->clone(),
            ECHVersion::Draft9);

        break;
      }
      default: {
        // We currently don't have an implementation
        // to decrypt this version.
        return folly::none;
      }
    }

    if (decryptionResult.has_value()) {
      // We've successfully decrypted the client hello.
      auto result = std::move(decryptionResult.value());
      try {
        auto expandedExtensions = substituteOuterExtensions(
            std::move(result.extensions), clientHelloOuter.extensions);
        result.extensions = std::move(expandedExtensions);
      } catch (const OuterExtensionsError& e) {
        throw FizzException(e.what(), AlertDescription::illegal_parameter);
      }
      result.originalEncoding = encodeHandshake(result);
      return result;
    }
  }
  return folly::none;
}
} // namespace

void ECHConfigManager::addDecryptionConfig(DecrypterParams decrypterParams) {
  configs_.push_back(std::move(decrypterParams));
}

folly::Optional<ClientHello> ECHConfigManager::decryptClientHello(
    const ClientHello& chlo) {
  // Check for the ECH extension
  auto it =
      findExtension(chlo.extensions, ExtensionType::encrypted_client_hello);
  if (it != chlo.extensions.end()) {
    return tryToDecodeECH(chlo, *it, configs_);
  }

  return folly::none;
}

} // namespace ech
} // namespace fizz
