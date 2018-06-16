/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/server/AeadTokenCipher.h>
#include <fizz/server/FizzServerContext.h>
#include <fizz/server/TicketCipher.h>

namespace fizz {
namespace server {

template <typename AeadType, typename CodecType, typename HkdfType>
class AeadTicketCipher : public TicketCipher {
 public:
  /**
   * Set the PSK context used for these tickets. The PSK context is used as
   * part of the key derivation so that different contexts will result in
   * different keys, preventing keys from one context from being used for
   * another.
   */
  explicit AeadTicketCipher(std::string pskContext)
      : tokenCipher_(std::vector<std::string>(
            {CodecType::Label.toString(), pskContext})) {}

  AeadTicketCipher()
      : tokenCipher_(std::vector<std::string>({CodecType::Label.toString()})) {}

  /**
   * Set ticket secrets to use for ticket encryption/decryption.
   * The first one will be used for encryption.
   * All secrets must be at least kMinTicketSecretLength long.
   */
  bool setTicketSecrets(const std::vector<folly::ByteRange>& ticketSecrets) {
    return tokenCipher_.setSecrets(ticketSecrets);
  }

  void setContext(const FizzServerContext* context) {
    context_ = context;
  }

  void setValidity(std::chrono::seconds validity) {
    validity_ = validity;
  }

  folly::Future<folly::Optional<std::pair<Buf, std::chrono::seconds>>> encrypt(
      ResumptionState resState) const override {
    auto encoded = CodecType::encode(std::move(resState));
    auto ticket = tokenCipher_.encrypt(std::move(encoded));
    if (!ticket) {
      return folly::none;
    } else {
      return std::make_pair(std::move(*ticket), validity_);
    }
  }

  folly::Future<std::pair<PskType, folly::Optional<ResumptionState>>> decrypt(
      std::unique_ptr<folly::IOBuf> encryptedTicket) const override {
    auto plaintext = tokenCipher_.decrypt(std::move(encryptedTicket));
    if (plaintext) {
      try {
        auto decoded = CodecType::decode(std::move(*plaintext), context_);
        return std::make_pair(PskType::Resumption, std::move(decoded));
      } catch (const std::exception& ex) {
        VLOG(6) << "Failed to decode ticket, ex=" << ex.what();
      }
    }

    return std::make_pair(PskType::Rejected, folly::none);
  }

 private:
  AeadTokenCipher<AeadType, HkdfType> tokenCipher_;

  std::chrono::seconds validity_{std::chrono::hours(1)};

  const FizzServerContext* context_ = nullptr;
};
} // namespace server
} // namespace fizz
