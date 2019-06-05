/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/protocol/clock/SystemClock.h>
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
            {CodecType::Label.toString(), pskContext})),
        clock_(std::make_shared<SystemClock>()) {}

  AeadTicketCipher()
      : tokenCipher_(std::vector<std::string>({CodecType::Label.toString()})),
        clock_(std::make_shared<SystemClock>()) {}

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

  /**
   * These two settings control the ticket's validity period. The handshake
   * validity refers to how long a ticket is considered valid from the initial
   * full handshake that authenticated it. This time carries over when a new
   * ticket is issued on a resumed connection. In practice, this means a full
   * handshake will be forced when a ticket's handshake is considered stale.
   *
   * A given ticket's ticket_lifetime is the remaining handshake validity
   * period, capped at the configured ticket validity.
   */

  void setHandshakeValidity(std::chrono::seconds validity) {
    handshakeValidity_ = validity;
  }

  void setTicketValidity(std::chrono::seconds validity) {
    ticketValidity_ = validity;
  }

  void setClock(std::shared_ptr<Clock> clock) {
    clock_ = std::move(clock);
  }

  folly::Future<folly::Optional<std::pair<Buf, std::chrono::seconds>>> encrypt(
      ResumptionState resState) const override {
    auto encoded = CodecType::encode(std::move(resState));
    auto ticket = tokenCipher_.encrypt(std::move(encoded));
    if (!ticket) {
      return folly::none;
    }
    auto now = clock_->getCurrentTime();

    auto remainingValid = std::chrono::duration_cast<std::chrono::seconds>(
        (resState.handshakeTime + handshakeValidity_) - now);

    // If handshake is in future, remainingValid will be longer than the actual
    // validity period. Set maximum to err on the safe side.
    if (remainingValid > handshakeValidity_) {
      remainingValid = handshakeValidity_;
    }

    if (remainingValid <= std::chrono::system_clock::duration::zero()) {
      return folly::none;
    } else {
      return std::make_pair(
          std::move(*ticket), std::min(remainingValid, ticketValidity_));
    }
  }

  folly::Future<std::pair<PskType, folly::Optional<ResumptionState>>> decrypt(
      std::unique_ptr<folly::IOBuf> encryptedTicket) const override {
    auto plaintext = tokenCipher_.decrypt(std::move(encryptedTicket));
    if (plaintext) {
      try {
        auto decoded = CodecType::decode(std::move(*plaintext), context_);
        if (decoded.handshakeTime + handshakeValidity_ <
            clock_->getCurrentTime()) {
          VLOG(6) << "Ticket handshake stale, rejecting.";
          return std::make_pair(PskType::Rejected, folly::none);
        }
        return std::make_pair(PskType::Resumption, std::move(decoded));
      } catch (const std::exception& ex) {
        VLOG(6) << "Failed to decode ticket, ex=" << ex.what();
      }
    }

    return std::make_pair(PskType::Rejected, folly::none);
  }

 private:
  AeadTokenCipher<AeadType, HkdfType> tokenCipher_;

  std::chrono::seconds ticketValidity_{std::chrono::hours(1)};
  std::chrono::seconds handshakeValidity_{std::chrono::hours(72)};
  std::shared_ptr<Clock> clock_;

  const FizzServerContext* context_ = nullptr;
};
} // namespace server
} // namespace fizz
