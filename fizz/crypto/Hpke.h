/*
 *  Copyright (c) 2019-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/aead/Aead.h>
#include <fizz/crypto/HpkeContext.h>

namespace fizz {
namespace hpke {

struct PskInputs {
    static inline std::unique_ptr<folly::IOBuf> defaultPsk = folly::IOBuf::copyBuffer("");
    static inline std::unique_ptr<folly::IOBuf> defaultId = folly::IOBuf::copyBuffer("");

    Mode mode;
    std::unique_ptr<folly::IOBuf> psk;
    std::unique_ptr<folly::IOBuf> id;

   PskInputs(Mode givenMode, std::unique_ptr<folly::IOBuf> givenPsk, std::unique_ptr<folly::IOBuf> givenId):
    mode(givenMode), psk(std::move(givenPsk)), id(std::move(givenId)) {
      bool gotPsk = folly::IOBufNotEqualTo()(psk, defaultPsk);
      bool gotPskId = folly::IOBufNotEqualTo()(id, defaultId);

      if (gotPsk != gotPskId) {
        throw std::runtime_error("Inconsistent PSK inputs");
      }

      if (gotPsk && (mode == Mode::Base ||
        mode == Mode::Auth)) {
        throw std::runtime_error("PSK input provided when not needed");
      }

      if (!gotPsk && (mode == Mode::Psk ||
        mode == Mode::AuthPsk)) {
        throw std::runtime_error("Missing required PSK input");
      }
    }
};

struct KeyScheduleParams {
  Mode mode;
  std::unique_ptr<folly::IOBuf> sharedSecret;
  std::unique_ptr<folly::IOBuf> info;
  folly::Optional<PskInputs> pskInputs;
  std::unique_ptr<Aead> cipher;
  std::unique_ptr<fizz::hpke::Hkdf> hkdf;
  std::unique_ptr<folly::IOBuf> suiteId;
};

HpkeContext keySchedule(KeyScheduleParams params);

} // namespace hpke
} // namespace fizz
