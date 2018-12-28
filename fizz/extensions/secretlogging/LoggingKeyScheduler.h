/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/protocol/KeyScheduler.h>

namespace fizz {

/**
 * LoggingKeyScheduler is saving the secrets by overriding getSecrets
 * so that they can be available later.
 */
class LoggingKeyScheduler : public KeyScheduler {
 public:
  using KeyScheduler::KeyScheduler;
  virtual ~LoggingKeyScheduler() = default;

  DerivedSecret getSecret(EarlySecrets s, folly::ByteRange transcript)
      const override;
  DerivedSecret getSecret(HandshakeSecrets s, folly::ByteRange transcript)
      const override;
  DerivedSecret getSecret(AppTrafficSecrets s) const override;

  std::vector<uint8_t> getClientEarlyTrafficSecret() const {
    if (!clientEarlyTrafficSecret_) {
      return std::vector<uint8_t>();
    }
    return clientEarlyTrafficSecret_->secret;
  }

  std::vector<uint8_t> getClientHandshakeTrafficSecret() const {
    if (!clientHandshakeTrafficSecret_) {
      return std::vector<uint8_t>();
    }
    return clientHandshakeTrafficSecret_->secret;
  }

  std::vector<uint8_t> getServerHandshakeTrafficSecret() const {
    if (!serverHandshakeTrafficSecret_) {
      return std::vector<uint8_t>();
    }
    return serverHandshakeTrafficSecret_->secret;
  }

  std::vector<uint8_t> getClientTrafficSecret() const {
    if (!clientTrafficSecret_) {
      return std::vector<uint8_t>();
    }
    return clientTrafficSecret_->secret;
  }

  std::vector<uint8_t> getServerTrafficSecret() const {
    if (!serverTrafficSecret_) {
      return std::vector<uint8_t>();
    }
    return serverTrafficSecret_->secret;
  }

 private:
  mutable folly::Optional<DerivedSecret> clientEarlyTrafficSecret_;
  mutable folly::Optional<DerivedSecret> clientHandshakeTrafficSecret_;
  mutable folly::Optional<DerivedSecret> serverHandshakeTrafficSecret_;
  mutable folly::Optional<DerivedSecret> clientTrafficSecret_;
  mutable folly::Optional<DerivedSecret> serverTrafficSecret_;
};

} // namespace fizz
