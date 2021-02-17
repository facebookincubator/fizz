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
      case ECHVersion::V7: {
        auto echExtension = getExtension<ech::EncryptedClientHello>(cursor);
        // Check if this ECH config record digest matches the ECH extension.
        const auto& currentRecordDigest =
            getRecordDigest(param.echConfig, echExtension.suite.kdf_id);
        if (!folly::IOBufEqualTo()(
                currentRecordDigest, echExtension.record_digest)) {
          continue;
        }

        // Decrypt client hello
        decryptionResult = tryToDecryptECH(
            clientHelloOuter,
            param.echConfig,
            echExtension.suite,
            echExtension.enc->clone(),
            echExtension.encrypted_ch->clone(),
            param.kex->clone(),
            ECHVersion::V7);
        break;
      }
      case ECHVersion::V8: {
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
            ECHVersion::V8);

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
      return std::move(decryptionResult.value());
    } else if (param.echConfig.version == ECHVersion::V7) {
      // Decryption unsuccessful, abort the connection.
      throw FizzException(
          "unable to successfully decrypt ECH",
          AlertDescription::decrypt_error);
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
