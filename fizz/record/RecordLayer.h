/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/protocol/Params.h>
#include <fizz/record/Types.h>
#include <folly/Optional.h>
#include <folly/io/IOBufQueue.h>

namespace fizz {

class ReadRecordLayer {
 public:
  virtual ~ReadRecordLayer() = default;

  /**
   * Reads a fragment from the record layer. Returns an empty optional if
   * insuficient data available. Throws if data malformed. On success, advances
   * buf the amount read.
   */
  virtual folly::Optional<TLSMessage> read(folly::IOBufQueue& buf) = 0;

  /**
   * Get a message from the record layer. Returns none if insufficient data was
   * available on the socket. Throws on parse error.
   */
  virtual folly::Optional<Param> readEvent(folly::IOBufQueue& socketBuf);

  /**
   * Check if there is decrypted but unparsed handshake data buffered.
   */
  virtual bool hasUnparsedHandshakeData() const;

  /**
   * Returns the current encryption level of the data that the read record layer
   * can process.
   */
  virtual EncryptionLevel getEncryptionLevel() const = 0;

 private:
  static folly::Optional<Param> decodeHandshakeMessage(folly::IOBufQueue& buf);

  folly::IOBufQueue unparsedHandshakeData_{
      folly::IOBufQueue::cacheChainLength()};
};

class WriteRecordLayer {
 public:
  virtual ~WriteRecordLayer() = default;

  virtual Buf write(TLSMessage&& msg) const = 0;

  Buf writeAlert(Alert&& alert) const {
    return write(TLSMessage{ContentType::alert, encode(std::move(alert))});
  }

  Buf writeAppData(std::unique_ptr<folly::IOBuf>&& appData) const {
    return write(TLSMessage{ContentType::application_data, std::move(appData)});
  }

  template <typename... Args>
  Buf writeHandshake(Buf&& encodedHandshakeMsg, Args&&... args) const {
    TLSMessage msg{ContentType::handshake, std::move(encodedHandshakeMsg)};
    addMessage(msg.fragment, std::forward<Args>(args)...);
    return write(std::move(msg));
  }

  void setProtocolVersion(ProtocolVersion version) const {
    auto realVersion = getRealDraftVersion(version);
    if (realVersion == ProtocolVersion::tls_1_3_21 ||
        realVersion == ProtocolVersion::tls_1_3_20) {
      recordVersion_ = ProtocolVersion::tls_1_0;
    } else {
      recordVersion_ = ProtocolVersion::tls_1_2;
    }

    if (realVersion == ProtocolVersion::tls_1_3_23 ||
        realVersion == ProtocolVersion::tls_1_3_22 ||
        realVersion == ProtocolVersion::tls_1_3_21 ||
        realVersion == ProtocolVersion::tls_1_3_20) {
      useAdditionalData_ = false;
    } else {
      useAdditionalData_ = true;
    }
  }

  virtual EncryptionLevel getEncryptionLevel() const = 0;

 protected:
  mutable ProtocolVersion recordVersion_{ProtocolVersion::tls_1_2};
  mutable bool useAdditionalData_{true};

 private:
  template <typename... Args>
  static void addMessage(Buf& buf, Buf&& add, Args&&... args) {
    buf->prependChain(std::move(add));
    addMessage(buf, std::forward<Args>(args)...);
  }

  static void addMessage(Buf& /*buf*/) {}
};
} // namespace fizz
