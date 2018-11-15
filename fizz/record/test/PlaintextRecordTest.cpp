/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <fizz/record/PlaintextRecordLayer.h>

#include <folly/String.h>

using namespace folly;
using namespace folly::io;

using testing::_;
using namespace testing;

namespace fizz {
namespace test {

class PlaintextRecordTest : public testing::Test {
 protected:
  PlaintextReadRecordLayer read_;
  PlaintextWriteRecordLayer write_;

  IOBufQueue queue_{IOBufQueue::cacheChainLength()};

  IOBufEqualTo eq_;

  Buf getBuf(const std::string& hex) {
    auto data = unhexlify(hex);
    return IOBuf::copyBuffer(data.data(), data.size());
  }

  void addToQueue(const std::string& hex) {
    queue_.append(getBuf(hex));
  }

  void expectSame(const Buf& buf, const std::string& hex) {
    auto str = buf->moveToFbString().toStdString();
    EXPECT_EQ(hexlify(str), hex);
  }
};

TEST_F(PlaintextRecordTest, TestReadEmpty) {
  EXPECT_FALSE(read_.read(queue_).hasValue());
}

TEST_F(PlaintextRecordTest, TestReadHandshake) {
  addToQueue("16030100050123456789");
  auto msg = read_.read(queue_);
  EXPECT_EQ(msg->type, ContentType::handshake);
  expectSame(msg->fragment, "0123456789");
  EXPECT_TRUE(queue_.empty());
}

TEST_F(PlaintextRecordTest, TestReadAlert) {
  addToQueue("15030100050123456789");
  auto msg = read_.read(queue_);
  EXPECT_EQ(msg->type, ContentType::alert);
  expectSame(msg->fragment, "0123456789");
  EXPECT_TRUE(queue_.empty());
}

TEST_F(PlaintextRecordTest, TestReadAppData) {
  addToQueue("17030100050123456789");
  EXPECT_ANY_THROW(read_.read(queue_));
}

TEST_F(PlaintextRecordTest, TestWaitForData) {
  addToQueue("160301000512345678");
  EXPECT_FALSE(read_.read(queue_).hasValue());
  EXPECT_EQ(queue_.chainLength(), 9);
}

TEST_F(PlaintextRecordTest, TestWaitForHeader) {
  addToQueue("16030102");
  EXPECT_FALSE(read_.read(queue_).hasValue());
  EXPECT_EQ(queue_.chainLength(), 4);
}

TEST_F(PlaintextRecordTest, TestMaxSize) {
  addToQueue("1603014000");
  EXPECT_FALSE(read_.read(queue_).hasValue());
  EXPECT_EQ(queue_.chainLength(), 5);
}

TEST_F(PlaintextRecordTest, TestOverSize) {
  addToQueue("1603014001");
  EXPECT_ANY_THROW(read_.read(queue_));
}

TEST_F(PlaintextRecordTest, TestEmpty) {
  addToQueue("1603010000aa");
  EXPECT_ANY_THROW(read_.read(queue_));
}

TEST_F(PlaintextRecordTest, TestDataRemaining) {
  addToQueue("16030100050123456789160301");
  auto msg = read_.read(queue_);
  EXPECT_EQ(msg->type, ContentType::handshake);
  expectSame(msg->fragment, "0123456789");
  EXPECT_EQ(queue_.chainLength(), 3);
  expectSame(queue_.move(), "160301");
}

TEST_F(PlaintextRecordTest, TestSkipAndWait) {
  read_.setSkipEncryptedRecords(true);
  addToQueue("17030100050123456789");
  EXPECT_FALSE(read_.read(queue_).hasValue());
  EXPECT_TRUE(queue_.empty());
}

TEST_F(PlaintextRecordTest, TestWaitBeforeSkip) {
  read_.setSkipEncryptedRecords(true);
  addToQueue("170301000501234567");
  EXPECT_FALSE(read_.read(queue_).hasValue());
  expectSame(queue_.move(), "170301000501234567");
}

TEST_F(PlaintextRecordTest, TestSkipAndRead) {
  read_.setSkipEncryptedRecords(true);
  addToQueue("170301000501234567891703010005012345678916030100050123456789");
  auto msg = read_.read(queue_);
  EXPECT_EQ(msg->type, ContentType::handshake);
  expectSame(msg->fragment, "0123456789");
  EXPECT_TRUE(queue_.empty());
}

TEST_F(PlaintextRecordTest, TestWriteHandshake) {
  TLSMessage msg{ContentType::handshake, getBuf("1234567890")};
  auto buf = write_.write(std::move(msg));
  expectSame(buf.data, "16030300051234567890");
}

TEST_F(PlaintextRecordTest, TestWriteClientHello) {
  auto buf = write_.writeInitialClientHello(getBuf("1234567890"));
  expectSame(buf.data, "16030100051234567890");
}

TEST_F(PlaintextRecordTest, TestWriteAppData) {
  TLSMessage msg{ContentType::application_data};
  EXPECT_ANY_THROW(write_.write(std::move(msg)));
}

TEST_F(PlaintextRecordTest, TestFragmentedWrite) {
  TLSMessage msg{ContentType::handshake, IOBuf::create(0)};
  auto buf = IOBuf::create(0x4010);
  buf->append(0x4010);
  memset(buf->writableData(), 0x1, buf->length());
  msg.fragment->prependChain(std::move(buf));
  auto write = write_.write(std::move(msg));

  TLSMessage msg1{ContentType::handshake, IOBuf::create(0)};
  buf = IOBuf::create(0x4000);
  buf->append(0x4000);
  memset(buf->writableData(), 0x1, buf->length());
  msg1.fragment->prependChain(std::move(buf));
  auto write1 = write_.write(std::move(msg1));

  TLSMessage msg2{ContentType::handshake, IOBuf::create(0)};
  buf = IOBuf::create(0x10);
  buf->append(0x10);
  memset(buf->writableData(), 0x1, buf->length());
  msg2.fragment->prependChain(std::move(buf));
  auto write2 = write_.write(std::move(msg2));

  write1.data->prependChain(std::move(write2.data));
  IOBufEqualTo eq;
  EXPECT_TRUE(eq(write.data, write1.data));
}
} // namespace test
} // namespace fizz
