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

  // Takes list of next protocols and determines the preferred protocol list
  // by item having the max weight
  static std::vector<std::string> getAlpnsFromNpnList(
      const std::list<folly::SSLContext::NextProtocolsItem>& list);

  static folly::ssl::EvpPkeyUniquePtr decryptPrivateKey(
      const std::string& data,
      folly::PasswordInFile* pf);

  // Creates a AES128TicketCipher with given params
  static std::shared_ptr<fizz::server::TicketCipher> createTicketCipher(
      const std::vector<std::string>& oldSecrets,
      const std::string& currentSecret,
      const std::vector<std::string>& newSecrets,
      std::chrono::seconds validity,
      std::string pskContext);
};

} // namespace fizz
