/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */
#include <fizz/util/FizzUtil.h>
#include <fizz/server/TicketTypes.h>

#include <folly/FileUtil.h>
#include <folly/Format.h>
#include <folly/io/async/SSLContext.h>
#include <folly/portability/OpenSSL.h>
#include <folly/ssl/Init.h>

#include <openssl/bio.h>

namespace fizz {

static int passwordCallback(char* password, int size, int, void* data) {
  if (!password || !data || size < 1) {
    LOG(ERROR) << "invalid password buffer, size is " << size;
    return 0;
  }
  std::string userPassword;
  static_cast<folly::PasswordInFile*>(data)->getPassword(userPassword, size);
  if (userPassword.empty()) {
    LOG(ERROR) << "empty private key password";
    return 0;
  }
  auto length = std::min(static_cast<int>(userPassword.size()), size - 1);
  memcpy(password, userPassword.data(), length);
  password[length] = '\0';
  return length;
}

std::vector<folly::ssl::X509UniquePtr> FizzUtil::readChainFile(
    const std::string& filename) {
  std::string certData;
  if (!folly::readFile(filename.c_str(), certData)) {
    throw std::runtime_error(
        folly::to<std::string>("couldn't read cert file: ", filename));
  }
  auto certRange = folly::ByteRange(folly::StringPiece(certData));
  auto certs = folly::ssl::OpenSSLCertUtils::readCertsFromBuffer(certRange);
  if (certs.empty()) {
    throw std::runtime_error(
        folly::to<std::string>("couldn't read any cert from: ", filename));
  }
  return certs;
}

folly::ssl::EvpPkeyUniquePtr FizzUtil::readPrivateKey(
    const std::string& filename,
    const std::string& passwordFilename) {
  std::string data;
  folly::readFile(filename.c_str(), data);
  try {
    if (!passwordFilename.empty()) {
      folly::PasswordInFile pf(passwordFilename);
      return FizzUtil::decryptPrivateKey(data, &pf);
    } else {
      return FizzUtil::decryptPrivateKey(data, nullptr);
    }
  } catch (std::runtime_error& e) {
    auto ex = folly::sformat(
        "Failed to read private key from file: {}, password file: {}",
        filename,
        passwordFilename);
    std::throw_with_nested(std::runtime_error(ex));
  }
}

folly::ssl::EvpPkeyUniquePtr FizzUtil::decryptPrivateKey(
    const std::string& data,
    folly::PasswordInFile* pf) {
  folly::ssl::BioUniquePtr keyBio(BIO_new_mem_buf(
      const_cast<void*>( // needed by openssl 1.0.2d
          reinterpret_cast<const void*>(data.data())),
      data.size()));
  if (!keyBio) {
    throw std::runtime_error("couldn't create bio");
  }

  folly::ssl::EvpPkeyUniquePtr pkey;
  if (pf) {
    pkey.reset(
        PEM_read_bio_PrivateKey(keyBio.get(), nullptr, passwordCallback, pf));
  } else {
    pkey.reset(
        PEM_read_bio_PrivateKey(keyBio.get(), nullptr, nullptr, nullptr));
  }

  if (!pkey) {
    throw std::runtime_error("couldn't read private key");
  }

  return pkey;
}

std::vector<std::string> FizzUtil::getAlpnsFromNpnList(
    const std::list<folly::SSLContext::NextProtocolsItem>& list) {
  CHECK(!list.empty());
  auto maxWeight = list.front().weight;
  auto protoList = &list.front().protocols;
  for (const auto& item : list) {
    if (item.weight > maxWeight) {
      protoList = &item.protocols;
    }
  }
  return std::vector<std::string>(protoList->begin(), protoList->end());
}
} // namespace fizz
