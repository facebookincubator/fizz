/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/extensions/secretlogging/LoggingKeyScheduler.h>
#include <fizz/protocol/Factory.h>

namespace fizz {

class LoggingFactory : public Factory {
 public:
  LoggingFactory() = default;
  virtual ~LoggingFactory() = default;

  virtual std::unique_ptr<KeyScheduler> makeKeyScheduler(
      CipherSuite cipher) const {
    auto keyDer = makeKeyDeriver(cipher);
    return std::make_unique<LoggingKeyScheduler>(std::move(keyDer));
  }
};

} // namespace fizz
