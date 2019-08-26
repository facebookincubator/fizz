/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <fizz/record/RecordLayer.h>
#include <fizz/record/test/Mocks.h>

#include <folly/String.h>

using namespace folly;

using testing::_;
using namespace testing;

namespace fizz {
namespace test {

class ConcreteReadRecordLayer : public PlaintextReadRecordLayer {
 public:
  MOCK_METHOD1(read, folly::Optional<TLSMessage>(folly::IOBufQueue& buf));
};

class ConcreteWriteRecordLayer : public PlaintextWriteRecordLayer {
 public:
  MOCK_CONST_METHOD1(_write, TLSContent(TLSMessage& msg));
  TLSContent write(TLSMessage&& msg) const override {
    return _write(msg);
  }
};

class RecordTest : public testing::Test {
 protected:
  StrictMock<ConcreteReadRecordLayer> read_;
  StrictMock<ConcreteWriteRecordLayer> write_;

  IOBufQueue queue_{IOBufQueue::cacheChainLength()};

  IOBufEqualTo eq_;

  static Buf getBuf(const std::string& hex) {
    auto data = unhexlify(hex);
    return IOBuf::copyBuffer(data.data(), data.size());
  }

  static void expectSame(const Buf& buf, const std::string& hex) {
    auto str = buf->moveToFbString().toStdString();
    EXPECT_EQ(hexlify(str), hex);
  }
};

TEST_F(RecordTest, TestNoData) {
  EXPECT_CALL(read_, read(_)).WillOnce(InvokeWithoutArgs([]() {
    return none;
  }));
  EXPECT_FALSE(read_.readEvent(queue_).hasValue());
}

TEST_F(RecordTest, TestReadAppData) {
  EXPECT_CALL(read_, read(_)).WillOnce(InvokeWithoutArgs([]() {
    return TLSMessage{ContentType::application_data, IOBuf::copyBuffer("hi")};
  }));
  auto param = read_.readEvent(queue_);
  auto& appData = boost::get<AppData>(*param);
  EXPECT_TRUE(eq_(appData.data, IOBuf::copyBuffer("hi")));
}

TEST_F(RecordTest, TestAlert) {
  EXPECT_CALL(read_, read(_)).WillOnce(InvokeWithoutArgs([]() {
    return TLSMessage{ContentType::alert, getBuf("0202")};
  }));
  auto param = read_.readEvent(queue_);
  boost::get<Alert>(*param);
}

TEST_F(RecordTest, TestHandshake) {
  EXPECT_CALL(read_, read(_)).WillOnce(InvokeWithoutArgs([]() {
    return TLSMessage{ContentType::handshake, getBuf("140000023232")};
  }));
  auto param = read_.readEvent(queue_);
  auto& finished = boost::get<Finished>(*param);
  expectSame(finished.verify_data, "3232");
  expectSame(*finished.originalEncoding, "140000023232");
}

TEST_F(RecordTest, TestHandshakeTooLong) {
  EXPECT_CALL(read_, read(_)).WillOnce(InvokeWithoutArgs([]() {
    return TLSMessage{ContentType::handshake, getBuf("14400000")};
  }));
  EXPECT_ANY_THROW(read_.readEvent(queue_));
}

TEST_F(RecordTest, TestHandshakeFragmentedImmediate) {
  EXPECT_CALL(read_, read(_))
      .WillOnce(InvokeWithoutArgs([]() {
        return TLSMessage{ContentType::handshake, getBuf("14000008aabbccdd")};
      }))
      .WillOnce(InvokeWithoutArgs([]() {
        return TLSMessage{ContentType::handshake, getBuf("11223344")};
      }));
  auto param = read_.readEvent(queue_);
  EXPECT_FALSE(read_.hasUnparsedHandshakeData());
  auto& finished = boost::get<Finished>(*param);
  expectSame(finished.verify_data, "aabbccdd11223344");
}

TEST_F(RecordTest, TestHandshakeFragmentedDelayed) {
  EXPECT_CALL(read_, read(_))
      .WillOnce(InvokeWithoutArgs([]() {
        return TLSMessage{ContentType::handshake, getBuf("14000008aabbccdd")};
      }))
      .WillOnce(InvokeWithoutArgs([]() { return folly::none; }));
  EXPECT_FALSE(read_.readEvent(queue_).hasValue());
  EXPECT_TRUE(read_.hasUnparsedHandshakeData());
  EXPECT_CALL(read_, read(_)).WillOnce(InvokeWithoutArgs([]() {
    return TLSMessage{ContentType::handshake, getBuf("11223344")};
  }));
  auto param = read_.readEvent(queue_);
  auto& finished = boost::get<Finished>(*param);
  expectSame(finished.verify_data, "aabbccdd11223344");
}

TEST_F(RecordTest, TestHandshakeCoalesced) {
  EXPECT_CALL(read_, read(_)).WillOnce(InvokeWithoutArgs([]() {
    return TLSMessage{ContentType::handshake,
                      getBuf("14000002aabb14000002ccdd")};
  }));
  auto param = read_.readEvent(queue_);
  auto& finished = boost::get<Finished>(*param);
  expectSame(finished.verify_data, "aabb");
  EXPECT_TRUE(read_.hasUnparsedHandshakeData());
  param = read_.readEvent(queue_);
  auto& finished2 = boost::get<Finished>(*param);
  expectSame(finished2.verify_data, "ccdd");
  EXPECT_FALSE(read_.hasUnparsedHandshakeData());
}

TEST_F(RecordTest, TestHandshakeSpliced) {
  EXPECT_CALL(read_, read(_))
      .WillOnce(InvokeWithoutArgs([]() {
        return TLSMessage{ContentType::handshake, getBuf("01000010abcd")};
      }))
      .WillOnce(InvokeWithoutArgs([]() {
        return TLSMessage{ContentType::application_data,
                          IOBuf::copyBuffer("hi")};
      }));
  EXPECT_ANY_THROW(read_.readEvent(queue_));
}

TEST_F(RecordTest, TestMultipleHandshakeMessages) {
  EXPECT_CALL(read_, read(_))
      .WillOnce(InvokeWithoutArgs([]() {
        return TLSMessage{ContentType::handshake,
                          getBuf("14000002aabb14000002")};
      }))
      .WillOnce(InvokeWithoutArgs([]() {
        // Really large message to force the record layer to
        // allocate more space as well the tail end of the previous
        // finished message
        auto message = getBuf("ccdd");
        for (size_t i = 0; i < 1000; ++i) {
          message->prependChain(getBuf("14000002aabb"));
        }
        message->coalesce();
        return TLSMessage{ContentType::handshake, std::move(message)};
      }));
  auto param = read_.readEvent(queue_);
  auto& finished = boost::get<Finished>(*param);
  expectSame(finished.verify_data, "aabb");
  EXPECT_TRUE(read_.hasUnparsedHandshakeData());
  param = read_.readEvent(queue_);
  auto& finished2 = boost::get<Finished>(*param);
  expectSame(finished2.verify_data, "ccdd");
  EXPECT_TRUE(read_.hasUnparsedHandshakeData());
}

TEST_F(RecordTest, TestWriteAppData) {
  EXPECT_CALL(write_, _write(_)).WillOnce(Invoke([&](TLSMessage& msg) {
    TLSContent content;
    content.contentType = msg.type;
    content.encryptionLevel = write_.getEncryptionLevel();
    content.data = nullptr;
    EXPECT_EQ(msg.type, ContentType::application_data);
    return content;
  }));
  write_.writeAppData(IOBuf::copyBuffer("hi"));
}

TEST_F(RecordTest, TestWriteAlert) {
  EXPECT_CALL(write_, _write(_)).WillOnce(Invoke([&](TLSMessage& msg) {
    EXPECT_EQ(msg.type, ContentType::alert);
    TLSContent content;
    content.contentType = msg.type;
    content.encryptionLevel = write_.getEncryptionLevel();
    content.data = nullptr;
    return content;
  }));
  write_.writeAlert(Alert());
}

TEST_F(RecordTest, TestWriteHandshake) {
  EXPECT_CALL(write_, _write(_)).WillOnce(Invoke([&](TLSMessage& msg) {
    EXPECT_EQ(msg.type, ContentType::handshake);
    TLSContent content;
    content.contentType = msg.type;
    content.encryptionLevel = write_.getEncryptionLevel();
    content.data = nullptr;
    return content;
  }));
  write_.writeHandshake(IOBuf::copyBuffer("msg1"), IOBuf::copyBuffer("msg2"));
}
} // namespace test
} // namespace fizz
