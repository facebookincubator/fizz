/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/extensions/secretlogging/LoggingKeyScheduler.h>

namespace fizz {

DerivedSecret LoggingKeyScheduler::getSecret(
    EarlySecrets s,
    folly::ByteRange transcript) const {
  auto secret = KeyScheduler::getSecret(s, transcript);
  switch (s) {
    case EarlySecrets::ClientEarlyTraffic:
      clientEarlyTrafficSecret_ = secret;
      break;
    default:
      break;
  }
  return secret;
}

DerivedSecret LoggingKeyScheduler::getSecret(
    HandshakeSecrets s,
    folly::ByteRange transcript) const {
  auto secret = KeyScheduler::getSecret(s, transcript);
  switch (s) {
    case HandshakeSecrets::ClientHandshakeTraffic:
      clientHandshakeTrafficSecret_ = secret;
      break;
    case HandshakeSecrets::ServerHandshakeTraffic:
      serverHandshakeTrafficSecret_ = secret;
      break;
  }
  return secret;
}

DerivedSecret LoggingKeyScheduler::getSecret(AppTrafficSecrets s) const {
  auto secret = KeyScheduler::getSecret(s);
  switch (s) {
    case AppTrafficSecrets::ClientAppTraffic:
      clientTrafficSecret_ = secret;
      break;
    case AppTrafficSecrets::ServerAppTraffic:
      serverTrafficSecret_ = secret;
      break;
  }
  return secret;
}

} // namespace fizz
