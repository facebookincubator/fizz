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
#include <fizz/server/TicketPolicy.h>

namespace fizz {
namespace server {

template <typename CodecType>
class Aead128GCMTicketCipher : public TicketCipher {
 public:
  /**
   * Set the PSK context used for these tickets. The PSK context is used as
   * part of the key derivation so that different contexts will result in
   * different keys, preventing keys from one context from being used for
   * another.
   */
  explicit Aead128GCMTicketCipher(std::string pskContext)
      : tokenCipher_(std::vector<std::string>(
            {CodecType::Label.toString(), pskContext})),
        policy_() {}

  Aead128GCMTicketCipher()
      : tokenCipher_(std::vector<std::string>({CodecType::Label.toString()})),
        policy_() {}

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

  /*
   * The ticket policy determines when tickets get rejected (even if they can be
   * encrypted/decrypted), for example if too much time has elapsed since the
   * full handshake that originally authenticated the server and/or client for
   * the session.
   */
  void setPolicy(TicketPolicy policy) {
    policy_ = std::move(policy);
  }

  folly::Future<folly::Optional<std::pair<Buf, std::chrono::seconds>>> encrypt(
      ResumptionState resState) const override {
    auto validity = policy_.remainingValidity(resState);
    if (validity <= std::chrono::system_clock::duration::zero()) {
      return folly::none;
    }

    auto encoded = CodecType::encode(std::move(resState));
    auto ticket = tokenCipher_.encrypt(std::move(encoded));
    if (!ticket) {
      return folly::none;
    }
    return std::make_pair(std::move(*ticket), validity);
  }

  folly::Future<std::pair<PskType, folly::Optional<ResumptionState>>> decrypt(
      std::unique_ptr<folly::IOBuf> encryptedTicket) const override {
    auto plaintext = tokenCipher_.decrypt(std::move(encryptedTicket));
    if (!plaintext) {
      return std::make_pair(PskType::Rejected, folly::none);
    }

    ResumptionState resState;
    try {
      resState = CodecType::decode(std::move(*plaintext), context_);
    } catch (const std::exception& ex) {
      VLOG(6) << "Failed to decode ticket, ex=" << ex.what();
      return std::make_pair(PskType::Rejected, folly::none);
    }

    if (!policy_.shouldAccept(resState)) {
      VLOG(6) << "Ticket failed acceptance policy.";
      return std::make_pair(PskType::Rejected, folly::none);
    }

    return std::make_pair(PskType::Resumption, std::move(resState));
  }

 private:
  Aead128GCMTokenCipher tokenCipher_;
  TicketPolicy policy_;

  const FizzServerContext* context_ = nullptr;
};
} // namespace server
} // namespace fizz
