/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/protocol/ech/Encryption.h>
#include <fizz/protocol/ech/Types.h>

namespace fizz {
namespace ech {

struct DecrypterParams {
  ECHConfig echConfig;
  std::unique_ptr<KeyExchange> kex;
};

class Decrypter {
 public:
  virtual ~Decrypter() = default;
  virtual folly::Optional<ClientHello> decryptClientHello(
      const ClientHello& chlo) = 0;
};

class ECHConfigManager : public Decrypter {
 public:
  void addDecryptionConfig(DecrypterParams decrypterParams);
  folly::Optional<ClientHello> decryptClientHello(
      const ClientHello& chlo) override;

 private:
  std::vector<DecrypterParams> configs_;
};

} // namespace ech
} // namespace fizz
