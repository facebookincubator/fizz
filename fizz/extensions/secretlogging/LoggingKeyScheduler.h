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

  std::vector<uint8_t> getSecret(EarlySecrets s, folly::ByteRange transcript)
      const override;
  std::vector<uint8_t> getSecret(
      HandshakeSecrets s,
      folly::ByteRange transcript) const override;
  std::vector<uint8_t> getSecret(AppTrafficSecrets s) const override;

  std::vector<uint8_t> getClientEarlyTrafficSecret() const {
    return clientEarlyTrafficSecret_;
  }

  std::vector<uint8_t> getClientHandshakeTrafficSecret() const {
    return clientHandshakeTrafficSecret_;
  }

  std::vector<uint8_t> getServerHandshakeTrafficSecret() const {
    return serverHandshakeTrafficSecret_;
  }

  std::vector<uint8_t> getClientTrafficSecret() const {
    return clientTrafficSecret_;
  }

  std::vector<uint8_t> getServerTrafficSecret() const {
    return serverTrafficSecret_;
  }

 private:
  mutable std::vector<uint8_t> clientEarlyTrafficSecret_;
  mutable std::vector<uint8_t> clientHandshakeTrafficSecret_;
  mutable std::vector<uint8_t> serverHandshakeTrafficSecret_;
  mutable std::vector<uint8_t> clientTrafficSecret_;
  mutable std::vector<uint8_t> serverTrafficSecret_;
};

} // namespace fizz
