/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <vector>

#include <folly/io/async/PasswordInFile.h>
#include <folly/ssl/OpenSSLCertUtils.h>

#include <fizz/extensions/tokenbinding/TokenBindingContext.h>
#include <fizz/protocol/Certificate.h>
#include <fizz/server/FizzServerContext.h>

namespace fizz {

class FizzUtil {
 public:
  // Read a vector of certs from a file
  static std::vector<folly::ssl::X509UniquePtr> readChainFile(
      const std::string& filename);

  static folly::ssl::EvpPkeyUniquePtr readPrivateKey(
      const std::string& filename,
      const std::string& passwordFilename);

  // Fizz does not yet support randomized next protocols so we use the highest
  // weighted list on the first context.
  static std::vector<std::string> getAlpnsFromNpnList(
      const std::list<folly::SSLContext::NextProtocolsItem>& list);

  static folly::ssl::EvpPkeyUniquePtr decryptPrivateKey(
      const std::string& data,
      folly::PasswordInFile* pf);

  // Creates a TicketCipher with given params
  template <class TicketCipher>
  static std::shared_ptr<TicketCipher> createTicketCipher(
      const std::vector<std::string>& oldSecrets,
      const std::string& currentSecret,
      const std::vector<std::string>& newSecrets,
      std::chrono::seconds validity,
      folly::Optional<std::string> pskContext) {
    std::vector<folly::ByteRange> ticketSecrets;
    if (!currentSecret.empty()) {
      ticketSecrets.push_back(folly::StringPiece(currentSecret));
    }
    for (const auto& secret : oldSecrets) {
      ticketSecrets.push_back(folly::StringPiece(secret));
    }
    for (const auto& secret : newSecrets) {
      ticketSecrets.push_back(folly::StringPiece(secret));
    }
    std::shared_ptr<TicketCipher> cipher;
    if (pskContext.hasValue()) {
      cipher = std::make_shared<TicketCipher>(std::move(*pskContext));
    } else {
      cipher = std::make_shared<TicketCipher>();
    }
    cipher->setTicketSecrets(std::move(ticketSecrets));
    cipher->setValidity(validity);
    return cipher;
  }
};

} // namespace fizz
