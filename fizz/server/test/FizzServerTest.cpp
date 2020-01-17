/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <fizz/server/FizzServer.h>
#include <fizz/server/test/Mocks.h>

using namespace folly;

namespace fizz {
namespace server {
namespace test {

class MockServerStateMachineInstance : public MockServerStateMachine {
 public:
  MockServerStateMachineInstance() {
    instance = this;
  }
  static MockServerStateMachineInstance* instance;
};
MockServerStateMachineInstance* MockServerStateMachineInstance::instance;

class ActionMoveVisitor {
 public:
  MOCK_METHOD0(fallback, void());

  template <typename T>
  void operator()(T&) {}

  void operator()(AttemptVersionFallback&) {
    fallback();
  }
};

class TestFizzServer : public DelayedDestruction {
 public:
  TestFizzServer() : fizzServer_(state_, queue_, visitor_, this) {}

  State state_;
  IOBufQueue queue_;
  ActionMoveVisitor visitor_;
  FizzServer<ActionMoveVisitor, MockServerStateMachineInstance> fizzServer_;
};

class FizzServerTest : public Test {
 public:
  void SetUp() override {
    context_ = std::make_shared<FizzServerContext>();
    fizzServer_.reset(new TestFizzServer());
  }

 protected:
  void accept() {
    EXPECT_CALL(
        *MockServerStateMachineInstance::instance, _processAccept(_, _, _, _))
        .WillOnce(InvokeWithoutArgs([] { return AsyncActions(Actions()); }));
    fizzServer_->fizzServer_.accept(&evb_, context_);
  }

  std::shared_ptr<FizzServerContext> context_;
  EventBase evb_;
  std::unique_ptr<TestFizzServer, DelayedDestruction::Destructor> fizzServer_;
};

TEST_F(FizzServerTest, TestAccept) {
  accept();
}

static std::unique_ptr<IOBuf> getV2ClientHello() {
  // This client hello is truncated but is sufficient to trigger the fallback.
  static constexpr StringPiece v2ClientHello =
      "808c0103010063000000200000390000380000350000";
  return IOBuf::copyBuffer(folly::unhexlify(v2ClientHello));
}

TEST_F(FizzServerTest, TestSSLV2) {
  context_->setVersionFallbackEnabled(true);
  accept();
  fizzServer_->queue_.append(getV2ClientHello());
  EXPECT_CALL(fizzServer_->visitor_, fallback());
  fizzServer_->fizzServer_.newTransportData();
}

TEST_F(FizzServerTest, TestSSLV2NoVersionFallback) {
  context_->setVersionFallbackEnabled(false);
  accept();
  fizzServer_->queue_.append(getV2ClientHello());
  EXPECT_CALL(
      *MockServerStateMachineInstance::instance, _processSocketData(_, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        fizzServer_->fizzServer_.waitForData();
        return AsyncActions(Actions());
      }));
  fizzServer_->fizzServer_.newTransportData();
}

TEST_F(FizzServerTest, TestNotSSLV2) {
  context_->setVersionFallbackEnabled(true);
  accept();
  fizzServer_->queue_.append(IOBuf::copyBuffer("ClientHello"));
  EXPECT_CALL(
      *MockServerStateMachineInstance::instance, _processSocketData(_, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        fizzServer_->fizzServer_.waitForData();
        return AsyncActions(Actions());
      }));
  fizzServer_->fizzServer_.newTransportData();
}

TEST_F(FizzServerTest, TestSSLV2AfterData) {
  context_->setVersionFallbackEnabled(true);
  accept();
  fizzServer_->queue_.append(IOBuf::copyBuffer("ClientHello"));
  EXPECT_CALL(
      *MockServerStateMachineInstance::instance, _processSocketData(_, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        fizzServer_->fizzServer_.waitForData();
        return AsyncActions(Actions());
      }));
  fizzServer_->fizzServer_.newTransportData();
  fizzServer_->queue_.clear();
  fizzServer_->queue_.append(getV2ClientHello());
  EXPECT_CALL(
      *MockServerStateMachineInstance::instance, _processSocketData(_, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        fizzServer_->fizzServer_.waitForData();
        return AsyncActions(Actions());
      }));
  fizzServer_->fizzServer_.newTransportData();
}

TEST(FizzServerContextTest, TestCopy) {
  FizzServerContext ctx;
  auto ctx2 = ctx;
  (void)ctx2;
}
} // namespace test
} // namespace server
} // namespace fizz
