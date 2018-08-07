/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/crypto/exchange/X25519.h>

#include <fizz/crypto/Utils.h>

#include <folly/Conv.h>
#include <sodium.h>

using namespace folly;

namespace fizz {

void X25519KeyExchange::generateKeyPair() {
  auto privKey = PrivKey();
  auto pubKey = PubKey();
  auto err = crypto_box_curve25519xsalsa20poly1305_keypair(
      pubKey.data(), privKey.data());
  if (err != 0) {
    throw std::runtime_error(to<std::string>("Could not generate keys ", err));
  }
  privKey_ = std::move(privKey);
  pubKey_ = std::move(pubKey);
}

std::unique_ptr<IOBuf> X25519KeyExchange::getKeyShare() const {
  if (!privKey_ || !pubKey_) {
    throw std::runtime_error("Key not generated");
  }
  return IOBuf::copyBuffer(pubKey_->data(), pubKey_->size());
}

std::unique_ptr<folly::IOBuf> X25519KeyExchange::generateSharedSecret(
    folly::ByteRange keyShare) const {
  if (!privKey_ || !pubKey_) {
    throw std::runtime_error("Key not generated");
  }
  if (keyShare.size() != crypto_scalarmult_BYTES) {
    throw std::runtime_error("Invalid external public key");
  }
  auto key = IOBuf::create(crypto_scalarmult_BYTES);
  key->append(crypto_scalarmult_BYTES);
  int err = crypto_scalarmult(
      key->writableData(), privKey_->data(), keyShare.data());
  if (err != 0) {
    throw std::runtime_error("Invalid point");
  }
  return key;
}
} // namespace fizz
