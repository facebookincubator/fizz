/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <fizz/protocol/AsyncFizzBase.h>

#include <folly/io/async/test/MockAsyncTransport.h>
#include <folly/io/async/test/MockTimeoutManager.h>

namespace fizz {
namespace test {

using namespace folly;
using namespace folly::test;
using namespace testing;

/**
 * The test class itself implements AsyncFizzBase so that it has access to the
 * app data interfaces.
 */
class AsyncFizzBaseTest : public testing::Test, public AsyncFizzBase {
 public:
  AsyncFizzBaseTest()
      : testing::Test(),
        AsyncFizzBase(
            AsyncTransportWrapper::UniquePtr(new MockAsyncTransport())) {
    socket_ = getUnderlyingTransport<MockAsyncTransport>();
    ON_CALL(*this, good()).WillByDefault(Return(true));
  }

  void TearDown() override {
    EXPECT_CALL(*socket_, setReadCB(nullptr));
  }

  MOCK_CONST_METHOD0(good, bool());
  MOCK_CONST_METHOD0(readable, bool());
  MOCK_CONST_METHOD0(connecting, bool());
  MOCK_CONST_METHOD0(error, bool());
  MOCK_CONST_METHOD0(getPeerCert, folly::ssl::X509UniquePtr());
  MOCK_CONST_METHOD0(getSelfCert, const X509*());
  MOCK_CONST_METHOD0(isReplaySafe, bool());
  MOCK_METHOD1(
      setReplaySafetyCallback,
      void(folly::AsyncTransport::ReplaySafetyCallback* callback));
  MOCK_CONST_METHOD0(getSelfCertificate, const Cert*());
  MOCK_CONST_METHOD0(getPeerCertificate, const Cert*());
  MOCK_CONST_METHOD0(getApplicationProtocol_, std::string());

  std::string getApplicationProtocol() const noexcept override {
    return getApplicationProtocol_();
  }

  MOCK_CONST_METHOD0(getCipher, folly::Optional<CipherSuite>());
  MOCK_CONST_METHOD0(getSupportedSigSchemes, std::vector<SignatureScheme>());
  MOCK_CONST_METHOD3(getEkm, Buf(folly::StringPiece, const Buf&, uint16_t));

  MOCK_METHOD3(
      writeAppDataInternal,
      void(
          folly::AsyncTransportWrapper::WriteCallback*,
          std::shared_ptr<folly::IOBuf>,
          folly::WriteFlags));

  void writeAppData(
      folly::AsyncTransportWrapper::WriteCallback* callback,
      std::unique_ptr<folly::IOBuf>&& buf,
      folly::WriteFlags flags = folly::WriteFlags::NONE) override {
    writeAppDataInternal(
        callback, std::shared_ptr<folly::IOBuf>(buf.release()), flags);
  }

  MOCK_METHOD1(transportError, void(const folly::AsyncSocketException&));
  MOCK_METHOD0(transportDataAvailable, void());

 protected:
  void expectReadBufRequest(size_t sizeToGive) {
    readBuf_.resize(sizeToGive);
    EXPECT_CALL(readCallback_, getReadBuffer(_, _))
        .InSequence(readBufSeq_)
        .WillOnce(DoAll(
            SetArgPointee<0>(readBuf_.data()),
            SetArgPointee<1>(readBuf_.size())));
  }

  void expectReadData(const std::string& data) {
    EXPECT_CALL(readCallback_, readDataAvailable_(data.size()))
        .InSequence(readBufSeq_)
        .WillOnce(Invoke([this, data](size_t len) {
          EXPECT_TRUE(std::memcmp(readBuf_.data(), data.data(), len) == 0);
        }));
  }

  void expectTransportReadCallback() {
    EXPECT_CALL(*socket_, setReadCB(_))
        .WillOnce(SaveArg<0>(&transportReadCallback_));
  }

  MockAsyncTransport* socket_;
  StrictMock<folly::test::MockReadCallback> readCallback_;
  ReadCallback* transportReadCallback_;
  AsyncSocketException ase_{AsyncSocketException::UNKNOWN, "unit test"};
  AsyncSocketException eof_{AsyncSocketException::END_OF_FILE, "unit test eof"};
  Sequence readBufSeq_;
  std::vector<uint8_t> readBuf_;
};

namespace {
class MockSecretCallback : public AsyncFizzBase::SecretCallback {
 public:
  MOCK_METHOD1(externalPskBinderAvailable_, void(const std::vector<uint8_t>&));
  void externalPskBinderAvailable(
      const std::vector<uint8_t>& secret) noexcept override {
    externalPskBinderAvailable_(secret);
  }
  MOCK_METHOD1(
      resumptionPskBinderAvailable_,
      void(const std::vector<uint8_t>&));
  void resumptionPskBinderAvailable(
      const std::vector<uint8_t>& secret) noexcept override {
    resumptionPskBinderAvailable_(secret);
  }
  MOCK_METHOD1(
      earlyExporterSecretAvailable_,
      void(const std::vector<uint8_t>&));
  void earlyExporterSecretAvailable(
      const std::vector<uint8_t>& secret) noexcept override {
    earlyExporterSecretAvailable_(secret);
  }
  MOCK_METHOD1(
      clientEarlyTrafficSecretAvailable_,
      void(const std::vector<uint8_t>&));
  void clientEarlyTrafficSecretAvailable(
      const std::vector<uint8_t>& secret) noexcept override {
    clientEarlyTrafficSecretAvailable_(secret);
  }
  MOCK_METHOD1(
      clientHandshakeTrafficSecretAvailable_,
      void(const std::vector<uint8_t>&));
  void clientHandshakeTrafficSecretAvailable(
      const std::vector<uint8_t>& secret) noexcept override {
    clientHandshakeTrafficSecretAvailable_(secret);
  }
  MOCK_METHOD1(
      serverHandshakeTrafficSecretAvailable_,
      void(const std::vector<uint8_t>&));
  void serverHandshakeTrafficSecretAvailable(
      const std::vector<uint8_t>& secret) noexcept override {
    serverHandshakeTrafficSecretAvailable_(secret);
  }
  MOCK_METHOD1(
      exporterMasterSecretAvailable_,
      void(const std::vector<uint8_t>&));
  void exporterMasterSecretAvailable(
      const std::vector<uint8_t>& secret) noexcept override {
    exporterMasterSecretAvailable_(secret);
  }
  MOCK_METHOD1(
      resumptionMasterSecretAvailable_,
      void(const std::vector<uint8_t>&));
  void resumptionMasterSecretAvailable(
      const std::vector<uint8_t>& secret) noexcept override {
    resumptionMasterSecretAvailable_(secret);
  }
  MOCK_METHOD1(
      clientAppTrafficSecretAvailable_,
      void(const std::vector<uint8_t>&));
  void clientAppTrafficSecretAvailable(
      const std::vector<uint8_t>& secret) noexcept override {
    clientAppTrafficSecretAvailable_(secret);
  }
  MOCK_METHOD1(
      serverAppTrafficSecretAvailable_,
      void(const std::vector<uint8_t>&));
  void serverAppTrafficSecretAvailable(
      const std::vector<uint8_t>& secret) noexcept override {
    serverAppTrafficSecretAvailable_(secret);
  }
};
} // namespace

MATCHER_P(BufMatches, expected, "") {
  folly::IOBufEqualTo eq;
  return eq(*arg, *expected);
}

TEST_F(AsyncFizzBaseTest, TestIsFizz) {
  EXPECT_EQ(getSecurityProtocol(), "Fizz");
}

TEST_F(AsyncFizzBaseTest, TestAppBytesWritten) {
  EXPECT_EQ(getAppBytesWritten(), 0);

  auto four = IOBuf::copyBuffer("4444");
  writeChain(nullptr, std::move(four));
  EXPECT_EQ(getAppBytesWritten(), 4);

  auto eight = IOBuf::copyBuffer("88888888");
  auto two = IOBuf::copyBuffer("22");
  eight->prependChain(std::move(two));
  writeChain(nullptr, std::move(eight));
  EXPECT_EQ(getAppBytesWritten(), 14);
}

TEST_F(AsyncFizzBaseTest, TestAppBytesReceived) {
  EXPECT_EQ(getAppBytesReceived(), 0);

  auto four = IOBuf::copyBuffer("4444");
  deliverAppData(std::move(four));
  EXPECT_EQ(getAppBytesReceived(), 4);

  auto eight = IOBuf::copyBuffer("88888888");
  auto two = IOBuf::copyBuffer("22");
  eight->prependChain(std::move(two));
  deliverAppData(std::move(eight));
  EXPECT_EQ(getAppBytesReceived(), 14);
}

TEST_F(AsyncFizzBaseTest, TestWrite) {
  auto buf = IOBuf::copyBuffer("buf");

  EXPECT_CALL(*this, writeAppDataInternal(_, _, _));
  writeChain(nullptr, std::move(buf));
}

TEST_F(AsyncFizzBaseTest, TestReadErr) {
  setReadCB(&readCallback_);

  EXPECT_CALL(readCallback_, readErr_(_));
  EXPECT_CALL(*socket_, close());
  deliverError(ase_);
  EXPECT_EQ(getReadCallback(), nullptr);
}

TEST_F(AsyncFizzBaseTest, TestReadErrNoCallback) {
  EXPECT_CALL(*socket_, close());
  deliverError(ase_);
}

TEST_F(AsyncFizzBaseTest, TestReadErrAsync) {
  ON_CALL(*this, good()).WillByDefault(Return(false));
  deliverError(ase_);

  EXPECT_CALL(readCallback_, readErr_(_));
  setReadCB(&readCallback_);
  EXPECT_EQ(getReadCallback(), nullptr);
}

TEST_F(AsyncFizzBaseTest, TestReadEOF) {
  setReadCB(&readCallback_);

  EXPECT_CALL(readCallback_, readEOF_());
  deliverError(eof_);
  EXPECT_EQ(getReadCallback(), nullptr);
}

TEST_F(AsyncFizzBaseTest, TestReadEOFNoCallback) {
  deliverError(eof_);
}

TEST_F(AsyncFizzBaseTest, TestMovableBuffer) {
  EXPECT_CALL(readCallback_, isBufferMovable_()).WillRepeatedly(Return(true));

  setReadCB(&readCallback_);

  auto buf = IOBuf::copyBuffer("buf");
  EXPECT_CALL(readCallback_, readBufferAvailable_(BufMatches(buf.get())));
  deliverAppData(buf->clone());

  auto buf2 = IOBuf::copyBuffer("buf2");
  EXPECT_CALL(readCallback_, readBufferAvailable_(BufMatches(buf2.get())));
  deliverAppData(buf2->clone());
}

TEST_F(AsyncFizzBaseTest, TestMovableBufferAsyncCallback) {
  EXPECT_CALL(readCallback_, isBufferMovable_()).WillRepeatedly(Return(true));

  auto buf = IOBuf::copyBuffer("buf");
  deliverAppData(std::move(buf));

  auto buf2 = IOBuf::copyBuffer("buf2");
  deliverAppData(std::move(buf2));

  auto expected = IOBuf::copyBuffer("bufbuf2");
  EXPECT_CALL(readCallback_, readBufferAvailable_(BufMatches(expected.get())));
  setReadCB(&readCallback_);

  auto buf3 = IOBuf::copyBuffer("buf3");
  EXPECT_CALL(readCallback_, readBufferAvailable_(BufMatches(buf3.get())));
  deliverAppData(buf3->clone());
}

TEST_F(AsyncFizzBaseTest, TestReadBufferLarger) {
  EXPECT_CALL(readCallback_, isBufferMovable_()).WillRepeatedly(Return(false));

  setReadCB(&readCallback_);

  auto buf = IOBuf::copyBuffer("sup");
  expectReadBufRequest(20);
  expectReadData("sup");
  deliverAppData(std::move(buf));
}

TEST_F(AsyncFizzBaseTest, TestReadBufferExact) {
  EXPECT_CALL(readCallback_, isBufferMovable_()).WillRepeatedly(Return(false));

  setReadCB(&readCallback_);

  auto buf = IOBuf::copyBuffer("sup");
  expectReadBufRequest(3);
  expectReadData("sup");
  deliverAppData(std::move(buf));
}

TEST_F(AsyncFizzBaseTest, TestReadBufferSmaller) {
  EXPECT_CALL(readCallback_, isBufferMovable_()).WillRepeatedly(Return(false));

  setReadCB(&readCallback_);

  auto buf = IOBuf::copyBuffer("hello");
  expectReadBufRequest(3);
  expectReadData("hel");
  expectReadBufRequest(3);
  expectReadData("lo");
  deliverAppData(std::move(buf));
}

TEST_F(AsyncFizzBaseTest, TestReadBufferAsync) {
  EXPECT_CALL(readCallback_, isBufferMovable_()).WillRepeatedly(Return(false));

  auto buf1 = IOBuf::copyBuffer("buf1");
  deliverAppData(std::move(buf1));
  auto buf2 = IOBuf::copyBuffer("buf2");
  deliverAppData(std::move(buf2));

  expectReadBufRequest(20);
  expectReadData("buf1buf2");
  setReadCB(&readCallback_);

  auto buf3 = IOBuf::copyBuffer("buf3");
  expectReadBufRequest(20);
  expectReadData("buf3");
  deliverAppData(std::move(buf3));
}

TEST_F(AsyncFizzBaseTest, TestReadBufferZero) {
  EXPECT_CALL(readCallback_, isBufferMovable_()).WillRepeatedly(Return(false));

  setReadCB(&readCallback_);

  auto buf = IOBuf::copyBuffer("hello");
  expectReadBufRequest(0);
  EXPECT_CALL(readCallback_, readErr_(_));
  EXPECT_CALL(*socket_, close());
  deliverAppData(std::move(buf));
}

TEST_F(AsyncFizzBaseTest, TestReadBufferPause) {
  EXPECT_CALL(readCallback_, isBufferMovable_()).WillRepeatedly(Return(false));

  setReadCB(&readCallback_);

  auto buf = IOBuf::copyBuffer("hello");
  expectReadBufRequest(3);
  EXPECT_CALL(readCallback_, readDataAvailable_(3))
      .InSequence(readBufSeq_)
      .WillOnce(Invoke([this](size_t len) {
        EXPECT_TRUE(std::memcmp(readBuf_.data(), "hel", len) == 0);
        this->setReadCB(nullptr);
      }));
  deliverAppData(std::move(buf));

  expectReadBufRequest(20);
  expectReadData("lo");
  setReadCB(&readCallback_);
}

TEST_F(AsyncFizzBaseTest, TestTransportReadBufMovable) {
  expectTransportReadCallback();
  startTransportReads();
  EXPECT_TRUE(transportReadCallback_->isBufferMovable());
}

TEST_F(AsyncFizzBaseTest, TestTransportReadBufMove) {
  IOBufEqualTo eq;
  expectTransportReadCallback();
  startTransportReads();

  auto buf = IOBuf::copyBuffer("hello");
  EXPECT_CALL(*this, transportDataAvailable());
  transportReadCallback_->readBufferAvailable(buf->clone());
  EXPECT_TRUE(eq(*buf, *transportReadBuf_.front()));

  EXPECT_CALL(*this, transportDataAvailable());
  transportReadCallback_->readBufferAvailable(IOBuf::copyBuffer("world"));
  EXPECT_TRUE(eq(*IOBuf::copyBuffer("helloworld"), *transportReadBuf_.front()));
}

TEST_F(AsyncFizzBaseTest, TestTransportReadBufAvail) {
  void* buf;
  size_t len;
  IOBufEqualTo eq;
  expectTransportReadCallback();
  startTransportReads();

  EXPECT_CALL(*this, transportDataAvailable());
  transportReadCallback_->getReadBuffer(&buf, &len);
  // Make sure the buffer is a reasonable size.
  EXPECT_GE(len, 128);
  EXPECT_LE(len, 1024 * 64);
  std::memcpy(buf, "hello", 5);
  transportReadCallback_->readDataAvailable(5);
  EXPECT_TRUE(eq(*IOBuf::copyBuffer("hello"), *transportReadBuf_.front()));

  EXPECT_CALL(*this, transportDataAvailable());
  transportReadCallback_->getReadBuffer(&buf, &len);
  std::memcpy(buf, "goodbye", 7);
  transportReadCallback_->readDataAvailable(7);
  EXPECT_TRUE(
      eq(*IOBuf::copyBuffer("hellogoodbye"), *transportReadBuf_.front()));
}

TEST_F(AsyncFizzBaseTest, TestTransportReadError) {
  expectTransportReadCallback();
  startTransportReads();

  EXPECT_CALL(*this, transportError(_));
  transportReadCallback_->readErr(ase_);
}

TEST_F(AsyncFizzBaseTest, TestTransportReadEOF) {
  expectTransportReadCallback();
  startTransportReads();

  EXPECT_CALL(*this, transportError(_))
      .WillOnce(Invoke([](const AsyncSocketException& ex) {
        EXPECT_EQ(ex.getType(), AsyncSocketException::END_OF_FILE);
      }));
  transportReadCallback_->readEOF();
}

TEST_F(AsyncFizzBaseTest, TestTransportReadBufPause) {
  expectTransportReadCallback();
  startTransportReads();

  auto bigBuf = IOBuf::create(1024 * 1024);
  bigBuf->append(1024 * 1024);
  expectTransportReadCallback();
  EXPECT_CALL(*this, transportDataAvailable());
  transportReadCallback_->readBufferAvailable(std::move(bigBuf));
  EXPECT_EQ(transportReadCallback_, nullptr);

  expectTransportReadCallback();
  setReadCB(&readCallback_);
  EXPECT_NE(transportReadCallback_, nullptr);
}

TEST_F(AsyncFizzBaseTest, TestAppReadBufPause) {
  EXPECT_CALL(readCallback_, isBufferMovable_()).WillRepeatedly(Return(true));
  expectTransportReadCallback();
  startTransportReads();

  auto bigBuf = IOBuf::create(1024 * 1024);
  bigBuf->append(1024 * 1024);
  expectTransportReadCallback();
  deliverAppData(std::move(bigBuf));
  EXPECT_EQ(transportReadCallback_, nullptr);

  expectTransportReadCallback();
  EXPECT_CALL(readCallback_, readBufferAvailable_(_));
  setReadCB(&readCallback_);
  EXPECT_NE(transportReadCallback_, nullptr);
}

TEST_F(AsyncFizzBaseTest, TestWriteSuccess) {
  AsyncTransportWrapper::WriteCallback* writeCallback = this;
  writeCallback->writeSuccess();
}

TEST_F(AsyncFizzBaseTest, TestWriteError) {
  AsyncTransportWrapper::WriteCallback* writeCallback = this;
  EXPECT_CALL(*this, transportError(_));
  writeCallback->writeErr(0, ase_);
}

TEST_F(AsyncFizzBaseTest, TestHandshakeTimeout) {
  MockTimeoutManager manager;
  ON_CALL(manager, isInTimeoutManagerThread()).WillByDefault(Return(true));
  attachTimeoutManager(&manager);
  AsyncTimeout* timeout;

  EXPECT_CALL(manager, scheduleTimeout(_, std::chrono::milliseconds(2)))
      .WillOnce(DoAll(SaveArg<0>(&timeout), Return(true)));
  startHandshakeTimeout(std::chrono::milliseconds(2));

  EXPECT_CALL(*this, transportError(_))
      .WillOnce(Invoke([](const AsyncSocketException& ex) {
        EXPECT_EQ(ex.getType(), AsyncSocketException::TIMED_OUT);
      }));
  timeout->timeoutExpired();
}

TEST_F(AsyncFizzBaseTest, TestAttachEventBase) {
  EventBase evb;
  expectTransportReadCallback();
  startTransportReads();
  ON_CALL(*socket_, good()).WillByDefault(Return(true));
  Sequence s;

  EXPECT_CALL(*socket_, setReadCB(nullptr)).InSequence(s);
  EXPECT_CALL(*socket_, detachEventBase()).InSequence(s);
  detachEventBase();

  EXPECT_CALL(*socket_, attachEventBase(&evb)).InSequence(s);
  EXPECT_CALL(*socket_, setReadCB(transportReadCallback_)).InSequence(s);
  attachEventBase(&evb);
}

TEST_F(AsyncFizzBaseTest, TestAttachEventBaseWithReadCb) {
  EventBase evb;
  expectTransportReadCallback();
  startTransportReads();
  ON_CALL(*socket_, good()).WillByDefault(Return(false));
  Sequence s;

  EXPECT_CALL(*socket_, setReadCB(nullptr)).InSequence(s);
  EXPECT_CALL(*socket_, detachEventBase()).InSequence(s);
  detachEventBase();

  expectTransportReadCallback();
  setReadCB(&readCallback_);
  EXPECT_CALL(*socket_, attachEventBase(&evb)).InSequence(s);
  EXPECT_CALL(*socket_, setReadCB(transportReadCallback_)).InSequence(s);
  attachEventBase(&evb);
}

TEST_F(AsyncFizzBaseTest, TestSecretAvailable) {
  MockSecretCallback cb;
  setSecretCallback(&cb);
  auto makeSecret = [](std::string secret, SecretType type) {
    std::vector<uint8_t> secretBuf(secret.begin(), secret.end());
    return DerivedSecret(std::move(secretBuf), type);
  };

  auto checkSecret = [](const DerivedSecret& expected) {
    return [&expected](const std::vector<uint8_t>& secret) {
      EXPECT_EQ(secret, expected.secret);
    };
  };

  auto exPskBinder =
      makeSecret("exPskBindSecret", EarlySecrets::ExternalPskBinder);
  EXPECT_CALL(cb, externalPskBinderAvailable_(_))
      .WillOnce(Invoke(checkSecret(exPskBinder)));
  secretAvailable(exPskBinder);

  auto resPskBinder =
      makeSecret("resPskBindSecret", EarlySecrets::ResumptionPskBinder);
  EXPECT_CALL(cb, resumptionPskBinderAvailable_(_))
      .WillOnce(Invoke(checkSecret(resPskBinder)));
  secretAvailable(resPskBinder);

  auto earlyExpSecret =
      makeSecret("earlyExpSecret", EarlySecrets::EarlyExporter);
  EXPECT_CALL(cb, earlyExporterSecretAvailable_(_))
      .WillOnce(Invoke(checkSecret(earlyExpSecret)));
  secretAvailable(earlyExpSecret);

  auto clientEarlySecret =
      makeSecret("clientEarlySecret", EarlySecrets::ClientEarlyTraffic);
  EXPECT_CALL(cb, clientEarlyTrafficSecretAvailable_(_))
      .WillOnce(Invoke(checkSecret(clientEarlySecret)));
  secretAvailable(clientEarlySecret);

  auto clientHandSecret =
      makeSecret("clientHandSecret", HandshakeSecrets::ClientHandshakeTraffic);
  EXPECT_CALL(cb, clientHandshakeTrafficSecretAvailable_(_))
      .WillOnce(Invoke(checkSecret(clientHandSecret)));
  secretAvailable(clientHandSecret);

  auto serverHandSecret =
      makeSecret("serverHandSecret", HandshakeSecrets::ServerHandshakeTraffic);
  EXPECT_CALL(cb, serverHandshakeTrafficSecretAvailable_(_))
      .WillOnce(Invoke(checkSecret(serverHandSecret)));
  secretAvailable(serverHandSecret);

  auto exporterMaster =
      makeSecret("exporterMaster", MasterSecrets::ExporterMaster);
  EXPECT_CALL(cb, exporterMasterSecretAvailable_(_))
      .WillOnce(Invoke(checkSecret(exporterMaster)));
  secretAvailable(exporterMaster);

  auto resumptionMaster =
      makeSecret("resumptionMaster", MasterSecrets::ResumptionMaster);
  EXPECT_CALL(cb, resumptionMasterSecretAvailable_(_))
      .WillOnce(Invoke(checkSecret(resumptionMaster)));
  secretAvailable(resumptionMaster);

  auto clientAppSecret =
      makeSecret("clientAppSecret", AppTrafficSecrets::ClientAppTraffic);
  EXPECT_CALL(cb, clientAppTrafficSecretAvailable_(_))
      .WillOnce(Invoke(checkSecret(clientAppSecret)));
  secretAvailable(clientAppSecret);

  auto serverAppSecret =
      makeSecret("serverAppSecret", AppTrafficSecrets::ServerAppTraffic);
  EXPECT_CALL(cb, serverAppTrafficSecretAvailable_(_))
      .WillOnce(Invoke(checkSecret(serverAppSecret)));
  secretAvailable(serverAppSecret);
}
} // namespace test
} // namespace fizz
