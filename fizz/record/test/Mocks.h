/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/record/EncryptedRecordLayer.h>
#include <fizz/record/PlaintextRecordLayer.h>

/* using override */
using namespace testing;

namespace fizz {

template <typename T>
void setWriteDefaults(T* obj) {
  ON_CALL(*obj, _write(_)).WillByDefault(Invoke([](TLSMessage& msg) {
    if (msg.type == ContentType::application_data) {
      return folly::IOBuf::copyBuffer("appdata");
    } else if (msg.type == ContentType::handshake) {
      return folly::IOBuf::copyBuffer("handshake");
    } else if (msg.type == ContentType::alert) {
      auto buf = folly::IOBuf::copyBuffer("alert");
      buf->prependChain(std::move(msg.fragment));
      buf->coalesce();
      return buf;
    } else {
      return std::unique_ptr<folly::IOBuf>();
    }
  }));
}

class MockPlaintextReadRecordLayer : public PlaintextReadRecordLayer {
 public:
  MOCK_METHOD1(read, folly::Optional<TLSMessage>(folly::IOBufQueue& buf));
  MOCK_CONST_METHOD0(hasUnparsedHandshakeData, bool());
  MOCK_METHOD1(setSkipEncryptedRecords, void(bool));
};

class MockEncryptedReadRecordLayer : public EncryptedReadRecordLayer {
 public:
  MOCK_METHOD1(read, folly::Optional<TLSMessage>(folly::IOBufQueue& buf));
  MOCK_CONST_METHOD0(hasUnparsedHandshakeData, bool());

  MOCK_METHOD1(_setAead, void(Aead*));
  void setAead(std::unique_ptr<Aead> aead) override {
    _setAead(aead.get());
  }

  MOCK_METHOD1(setSkipFailedDecryption, void(bool));
};

class MockPlaintextWriteRecordLayer : public PlaintextWriteRecordLayer {
 public:
  MOCK_CONST_METHOD1(_write, Buf(TLSMessage& msg));
  Buf write(TLSMessage&& msg) const override {
    return _write(msg);
  }

  MOCK_CONST_METHOD1(_writeInitialClientHello, Buf(Buf&));
  Buf writeInitialClientHello(Buf encoded) const override {
    return _writeInitialClientHello(encoded);
  }

  void setDefaults() {
    setWriteDefaults(this);
    ON_CALL(*this, _writeInitialClientHello(_))
        .WillByDefault(InvokeWithoutArgs(
            []() { return folly::IOBuf::copyBuffer("handshake"); }));
  }
};

class MockEncryptedWriteRecordLayer : public EncryptedWriteRecordLayer {
 public:
  MOCK_CONST_METHOD1(_write, Buf(TLSMessage& msg));
  Buf write(TLSMessage&& msg) const override {
    return _write(msg);
  }

  MOCK_METHOD1(_setAead, void(Aead*));
  void setAead(std::unique_ptr<Aead> aead) override {
    _setAead(aead.get());
  }

  void setDefaults() {
    setWriteDefaults(this);
  }
};
} // namespace fizz
