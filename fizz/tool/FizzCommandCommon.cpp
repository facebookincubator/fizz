/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/tool/FizzCommandCommon.h>
#include <fizz/protocol/ech/Types.h>
#include <folly/FileUtil.h>
#include <folly/String.h>

using namespace folly;

namespace fizz {
namespace tool {

int parseArguments(
    std::vector<std::string> argv,
    FizzArgHandlerMap handlers,
    std::function<void()> usageFunc) {
  for (size_t idx = 2; idx < argv.size(); idx++) {
    auto& argument = argv[idx];
    auto handlerIter = handlers.find(argument);

    // Ignore these.
    if (argument == "-v" || argument == "-vmodule") {
      idx++;
      continue;
    }

    if (handlerIter != handlers.end()) {
      auto& handlerInfo = handlerIter->second;
      std::string variable;
      if (handlerInfo.hasVariable) {
        if (idx + 1 >= argv.size()) {
          std::cerr << "Argument " << argument << " requires an parameter."
                    << std::endl;
          usageFunc();
          return 1;
        } else {
          idx++;
          variable = argv[idx];
        }
      }
      handlerInfo.handler(variable);
    } else {
      std::cerr << "Unknown argument: " << argument << std::endl;
      usageFunc();
      return 1;
    }
  }
  return 0;
}

TerminalInputHandler::TerminalInputHandler(
    EventBase* evb,
    InputHandlerCallback* cb)
    : EventHandler(evb, folly::NetworkSocket::fromFd(0)), cb_(cb), evb_(evb) {
  registerHandler(EventHandler::READ | EventHandler::PERSIST);
}

void TerminalInputHandler::handlerReady(uint16_t events) noexcept {
  // Handle read ready on stdin, but only once we're connected.
  if (events & EventHandler::READ && cb_->connected()) {
    std::array<char, 512> buf;
    int result = read(0, buf.data(), buf.size());

    if (result > 0) {
      cb_->write(IOBuf::wrapBuffer(buf.data(), result));
    } else {
      if (result < 0) {
        LOG(ERROR) << "Error on terminal read: " << folly::errnoStr(errno);
      }
      hitEOF();
    }
  }
}

void TerminalInputHandler::hitEOF() {
  evb_->runInLoop([cb_ = cb_]() { cb_->close(); });
}

std::vector<Extension> getExtensions(folly::StringPiece hex) {
  auto buf = folly::IOBuf::copyBuffer(folly::unhexlify(hex.toString()));
  folly::io::Cursor cursor(buf.get());
  Extension ext;
  CHECK_EQ(detail::read(ext, cursor), buf->computeChainDataLength());
  CHECK(cursor.isAtEnd());
  std::vector<Extension> exts;
  exts.push_back(std::move(ext));
  return exts;
}

hpke::KEMId getKEMId(std::string kemStr) {
  if (kemStr == "secp256r1") {
    return hpke::KEMId::secp256r1;
  } else if (kemStr == "secp384r1") {
    return hpke::KEMId::secp384r1;
  } else if (kemStr == "secp521r1") {
    return hpke::KEMId::secp521r1;
  } else if (kemStr == "x25519") {
    return hpke::KEMId::x25519;
  }

  // Input doesn't match any KEM id.
  throw std::runtime_error("Input doesn't match any KEM id");
};

folly::Optional<folly::dynamic> readECHConfigsJson(std::string echFile) {
  if (echFile.empty()) {
    throw std::runtime_error("No file provided");
  }

  std::string echConfigJson;
  if (!folly::readFile(echFile.c_str(), echConfigJson)) {
    throw std::runtime_error("Unable to read file provided");
  }

  auto json = folly::parseJson(echConfigJson);
  if (!json.isObject()) {
    throw std::runtime_error(
        "Unable to parse ECH configs JSON. Please ensure the file matches what is expected."
        "The format is roughly { echconfigs: [ ECHConfig{fields..} ] }."
        "For an actual example, see the test file.");
  }

  return json;
}

folly::Optional<std::vector<ech::ECHConfig>> parseECHConfigs(
    folly::dynamic json) {
  auto getKDFId = [](std::string kdfStr) {
    if (kdfStr == "Sha256") {
      return hpke::KDFId::Sha256;
    } else if (kdfStr == "Sha384") {
      return hpke::KDFId::Sha384;
    } else if (kdfStr == "Sha512") {
      return hpke::KDFId::Sha512;
    }

    // Input doesn't match any KDF id.
    throw std::runtime_error("Input doesn't match any KDF id");
  };

  auto getAeadId = [](std::string aeadStr) {
    if (aeadStr == "TLS_AES_128_GCM_SHA256") {
      return hpke::AeadId::TLS_AES_128_GCM_SHA256;
    } else if (aeadStr == "TLS_AES_256_GCM_SHA384") {
      return hpke::AeadId::TLS_AES_256_GCM_SHA384;
    } else if (aeadStr == "TLS_CHACHA20_POLY1305_SHA256") {
      return hpke::AeadId::TLS_CHACHA20_POLY1305_SHA256;
    }

    // Input doesn't match any Aead id.
    throw std::runtime_error("Input doesn't match any Aead id");
  };

  auto echConfigs = std::vector<ech::ECHConfig>();
  for (const auto& config : json["echconfigs"]) {
    std::string version = config["version"].asString();
    if (version != "V7") {
      return folly::none;
    }
    ech::ECHConfigContentDraft7 configContent;
    configContent.public_name =
        folly::IOBuf::copyBuffer(config["public_name"].asString());
    configContent.public_key = folly::IOBuf::copyBuffer(
        folly::unhexlify(config["public_key"].asString()));
    configContent.kem_id = getKEMId(config["kem_id"].asString());
    configContent.maximum_name_length = config["maximum_name_length"].asInt();

    // Get ciphersuites.
    auto ciphersuites = std::vector<ech::ECHCipherSuite>();
    for (size_t suiteIndex = 0; suiteIndex < config["cipher_suites"].size();
          ++suiteIndex) {
      const auto& suite = config["cipher_suites"][suiteIndex];

      ech::ECHCipherSuite parsedSuite;
      parsedSuite.kdf_id = getKDFId(suite["kdf_id"].asString());
      parsedSuite.aead_id = getAeadId(suite["aead_id"].asString());

      ciphersuites.push_back(parsedSuite);
    }
    configContent.cipher_suites = ciphersuites;

    // Get extensions.
    configContent.extensions = getExtensions(config["extensions"].asString());

    ech::ECHConfig parsedConfig;
    parsedConfig.version = ech::ECHVersion::V7;
    parsedConfig.ech_config_content = encode(std::move(configContent));
    echConfigs.push_back(parsedConfig);
  }
  return std::move(echConfigs);
}

} // namespace tool
} // namespace fizz
