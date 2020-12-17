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
ClientHello decryptClientHello(
    const ClientHello& clientHelloOuter,
    const ECHConfig& echConfig,
    const EncryptedClientHello& echExtension,
    std::unique_ptr<KeyExchange> kex) {
  auto decryptionResult = tryToDecryptECH(
      clientHelloOuter,
      echConfig,
      echExtension.suite,
      echExtension.enc->clone(),
      echExtension.encrypted_ch->clone(),
      std::move(kex),
      ECHVersion::V7);

  if (decryptionResult.has_value()) {
    // We've successfully decrypted the client hello.
    return std::move(decryptionResult.value());
  } else {
    // Decryption unsuccessful, abort the connection.
    throw FizzException(
        "unable to successfully decrypt ECH", AlertDescription::decrypt_error);
  }
}

folly::Optional<ClientHello> tryToDecodeECH(
    const ClientHello& chloOuter,
    const EncryptedClientHello& echExtension,
    const std::vector<DecrypterParams>& decrypterParams) {
  for (const auto& param : decrypterParams) {
    switch (param.echConfig.version) {
      case ECHVersion::V7: {
        // Check if this ECH config record digest matches the ECH extension.
        const auto& currentRecordDigest = getRecordDigest(
            param.echConfig,
            echExtension.suite.kdf_id);
        if (!folly::IOBufEqualTo()(
                currentRecordDigest, echExtension.record_digest)) {
          continue;
        }

        // Try to decode and get the client hello inner.
        return decryptClientHello(
            chloOuter,
            param.echConfig,
            echExtension,
            param.kex->clone());
      }
      default: {
        // We currently don't have an implementation
        // to decrypt this version.
        break;
      }
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
  auto it =
      findExtension(chlo.extensions, ExtensionType::encrypted_client_hello);

  if (it == chlo.extensions.end()) {
    return folly::none;
  }
  folly::io::Cursor cursor(it->extension_data.get());
  auto echExtension = getExtension<ech::EncryptedClientHello>(cursor);
  return tryToDecodeECH(chlo, echExtension, configs_);
}

} // namespace ech
} // namespace fizz
