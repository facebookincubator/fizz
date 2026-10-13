/*
 *  Copyright (c), Meta Platforms, Inc. and affiliates
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/experimental/psp/PSP.h>
#include <fizz/protocol/test/Mocks.h>
#include <folly/futures/Future.h>
#include <folly/io/async/AsyncSocket.h>
#include <folly/io/async/test/MockAsyncSocket.h>
#include <folly/io/async/test/MockAsyncTransport.h>
#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <array>

using namespace testing;

namespace {

class MockKernelPSP : public ::fizz::psp::KernelPSP {
 public:
  MOCK_METHOD(
      folly::SemiFuture<::fizz::psp::SA>,
      rxAssoc,
      (fizz::psp::PSPVersion version, int fd),
      (noexcept, override));
  MOCK_METHOD(
      folly::SemiFuture<folly::Unit>,
      txAssoc,
      (const struct ::fizz::psp::SA& sa, int fd),
      (noexcept, override));
};

class MockCallback : public ::fizz::psp::Callback {
 public:
  MOCK_METHOD(
      void,
      pspSuccess,
      (folly::NetworkSocket fd, std::unique_ptr<folly::IOBuf> postTlsData),
      (noexcept, override));
  MOCK_METHOD(
      void,
      pspError,
      (const folly::exception_wrapper& ew),
      (noexcept, override));
};

class AsyncPSPUpgradeV1Test : public ::testing::Test {
 protected:
  void SetUp() override {
    mockAsyncSocket_.reset(new folly::test::MockAsyncSocket(&evb_));
    ON_CALL(*mockAsyncSocket_, getNetworkSocket())
        .WillByDefault(Return(folly::NetworkSocket::fromFd(kFd)));

    // AsyncFizzBase only exposes its wrapped transport as const.
    inner_ = dynamic_cast<folly::test::MockAsyncTransport*>(
        const_cast<folly::AsyncTransport*>(transport_.getWrappedTransport()));
    ASSERT_NE(inner_, nullptr);
    ON_CALL(*inner_, getEventBase()).WillByDefault(Return(&evb_));
    ON_CALL(*inner_, getWrappedTransport())
        .WillByDefault(Return(mockAsyncSocket_.get()));

    EXPECT_CALL(transport_, setReadCB(_)).Times(AnyNumber());
    EXPECT_CALL(transport_, setEndOfTLSCallback(_)).Times(AnyNumber());
  }

  std::shared_ptr<fizz::psp::KernelPSP> kernelPSP() {
    return std::shared_ptr<MockKernelPSP>(
        std::shared_ptr<void>(), &mockKernelPSP_);
  }

  static fizz::psp::SA makeSA() {
    fizz::psp::SA sa;
    sa.psp_version = static_cast<uint8_t>(fizz::psp::PSPVersion::VER0);
    sa.spi = 0x11223344;
    sa.key.resize(16);
    memset(sa.key.data(), 0xfe, 16);
    return sa;
  }

  static void expectError(folly::IOBuf& buf, uint8_t code) {
    auto expected = std::to_array<uint8_t>({0x00, 0x01, code});
    folly::ByteRange msg = buf.coalesce();
    ASSERT_EQ(msg.size(), 3);
    EXPECT_EQ(memcmp(expected.data(), msg.data(), 3), 0);
  }

  std::unique_ptr<fizz::psp::AsyncPSPUpgradeFrame> makeUpgrade() {
    return fizz::psp::pspUpgradeV1(
        &transport_, fizz::psp::PSPVersion::VER0, kernelPSP());
  }

  // Drives the upgrade up to the point where it awaits the peer's SA.
  void startAndAwaitPeerSA(std::chrono::milliseconds timeout = {}) {
    EXPECT_CALL(mockKernelPSP_, rxAssoc(fizz::psp::PSPVersion::VER0, kFd))
        .WillOnce(Return(folly::makeSemiFuture(makeSA())));
    EXPECT_CALL(transport_, setEndOfTLSCallback(NotNull()))
        .WillOnce(SaveArg<0>(&endOfTLSCallback_));
    EXPECT_CALL(transport_, writeAppDataInternal(_, _, _))
        .WillOnce([](auto* cb, auto buf, auto) {
          ASSERT_NE(cb, nullptr);
          auto written = buf->coalesce();
          auto saMsg =
              folly::IOBuf::wrapBuffer(written.data() + 2, written.size() - 2);
          EXPECT_TRUE(fizz::psp::detail::tryDecodeSA(std::move(saMsg)));
          cb->writeSuccess();
        });
    EXPECT_CALL(transport_, setReadCB(NotNull()))
        .WillOnce(SaveArg<0>(&readCallback_));

    upgrade_ = makeUpgrade();
    upgrade_->start(&mockCallback_, timeout);
    // Not loop(), which would also run a pending timeout to completion.
    while (!readCallback_) {
      evb_.loopOnce(EVLOOP_NONBLOCK);
    }
    ASSERT_NE(endOfTLSCallback_, nullptr);
  }

  // Delivers the peer's SA, after which the upgrade awaits its close_notify.
  void peerSendsSA() {
    EXPECT_CALL(transport_, tlsShutdown());
    readCallback_->readBufferAvailable(fizz::psp::detail::encodeTLV(makeSA()));
  }

  static constexpr int kFd = 12345;

  folly::EventBase evb_;
  folly::test::MockAsyncSocket::UniquePtr mockAsyncSocket_;
  NiceMock<fizz::test::MockAsyncFizzBase> transport_;
  folly::test::MockAsyncTransport* inner_{nullptr};
  StrictMock<MockKernelPSP> mockKernelPSP_;
  StrictMock<MockCallback> mockCallback_;
  std::unique_ptr<fizz::psp::AsyncPSPUpgradeFrame> upgrade_;
  folly::AsyncTransport::ReadCallback* readCallback_{nullptr};
  fizz::AsyncFizzBase::EndOfTLSCallback* endOfTLSCallback_{nullptr};
};

TEST_F(AsyncPSPUpgradeV1Test, DestroyWithoutInitiating) {
  makeUpgrade();
}

TEST_F(AsyncPSPUpgradeV1Test, NonFileDescriptorTransportError) {
  ON_CALL(*mockAsyncSocket_, getNetworkSocket())
      .WillByDefault(Return(folly::NetworkSocket()));
  EXPECT_CALL(transport_, writeAppDataInternal(_, _, _))
      .WillOnce([](auto, auto buf, auto) { expectError(*buf, 0); });
  EXPECT_CALL(mockCallback_, pspError(_)).WillOnce([](auto& ew) {
    EXPECT_THAT(ew.get_exception()->what(), HasSubstr("invalid socket"));
  });

  makeUpgrade()->start(&mockCallback_);
}

TEST_F(AsyncPSPUpgradeV1Test, RxAssocFails) {
  EXPECT_CALL(mockKernelPSP_, rxAssoc(fizz::psp::PSPVersion::VER0, kFd))
      .WillOnce(Return(
          folly::makeSemiFuture<fizz::psp::SA>(
              folly::make_exception_wrapper<std::runtime_error>(
                  "dummy failure"))));
  EXPECT_CALL(transport_, writeAppDataInternal(_, _, _))
      .WillOnce([](auto, auto buf, auto) { expectError(*buf, 1); });
  EXPECT_CALL(mockCallback_, pspError(_)).WillOnce([](auto& ew) {
    EXPECT_THAT(ew.get_exception()->what(), HasSubstr("psp_rx_assoc failed"));
  });

  auto upgrade = makeUpgrade();
  upgrade->start(&mockCallback_);
  evb_.loop();
}

TEST_F(AsyncPSPUpgradeV1Test, WriteSAFails) {
  EXPECT_CALL(mockKernelPSP_, rxAssoc(fizz::psp::PSPVersion::VER0, kFd))
      .WillOnce(Return(folly::makeSemiFuture(makeSA())));
  EXPECT_CALL(transport_, writeAppDataInternal(_, _, _))
      .WillOnce([](auto* cb, auto, auto) {
        cb->writeErr(
            0,
            folly::AsyncSocketException(
                folly::AsyncSocketException::NETWORK_ERROR,
                "connection reset by peer"));
      });
  EXPECT_CALL(mockCallback_, pspError(_)).WillOnce([](auto& ew) {
    EXPECT_THAT(ew.get_exception()->what(), HasSubstr("write sa failed"));
  });

  auto upgrade = makeUpgrade();
  upgrade->start(&mockCallback_);
  evb_.loop();
}

TEST_F(AsyncPSPUpgradeV1Test, PeerSendsFailure) {
  startAndAwaitPeerSA();
  EXPECT_CALL(mockCallback_, pspError(_)).WillOnce([](auto& ew) {
    EXPECT_THAT(
        ew.get_exception()->what(), HasSubstr("peer signaled error: 125"));
  });

  auto failureMsg = std::to_array<uint8_t>({0x00, 0x01, 125});
  readCallback_->readBufferAvailable(
      folly::IOBuf::copyBuffer(failureMsg.data(), failureMsg.size()));
}

TEST_F(AsyncPSPUpgradeV1Test, PeerSendsInvalidSAMessage) {
  startAndAwaitPeerSA();
  EXPECT_CALL(mockCallback_, pspError(_)).WillOnce([](auto& ew) {
    EXPECT_THAT(
        ew.get_exception()->what(),
        HasSubstr("invalid or unsupported psp version"));
  });

  auto sa = makeSA();
  sa.psp_version = 123;
  readCallback_->readBufferAvailable(fizz::psp::detail::encodeTLV(sa));
}

TEST_F(AsyncPSPUpgradeV1Test, PeerEOFAwaitingSA) {
  startAndAwaitPeerSA();
  EXPECT_CALL(mockCallback_, pspError(_)).WillOnce([](auto& ew) {
    EXPECT_THAT(
        ew.get_exception()->what(), HasSubstr("read peer sa I/O error"));
  });

  readCallback_->readEOF();
}

TEST_F(AsyncPSPUpgradeV1Test, PeerSendsDataAfterSA) {
  // Anything the peer sends between its SA and its close_notify is lost to
  // PSP, so it must fail the upgrade.
  startAndAwaitPeerSA();
  EXPECT_CALL(mockCallback_, pspError(_)).WillOnce([](auto& ew) {
    EXPECT_THAT(
        ew.get_exception()->what(),
        HasSubstr("peer sent tls data after its sa"));
  });

  auto buf = fizz::psp::detail::encodeTLV(makeSA());
  buf->appendToChain(folly::IOBuf::copyBuffer("extra"));
  readCallback_->readBufferAvailable(std::move(buf));
}

TEST_F(AsyncPSPUpgradeV1Test, PeerEndsTLSBeforeSA) {
  startAndAwaitPeerSA();
  EXPECT_CALL(mockCallback_, pspError(_)).WillOnce([](auto& ew) {
    EXPECT_THAT(
        ew.get_exception()->what(),
        HasSubstr("peer ended tls before sending its sa"));
  });

  endOfTLSCallback_->endOfTLS(&transport_, nullptr);
}

TEST_F(AsyncPSPUpgradeV1Test, PeerEOFAwaitingCloseNotify) {
  startAndAwaitPeerSA();
  peerSendsSA();
  EXPECT_CALL(mockCallback_, pspError(_)).WillOnce([](auto& ew) {
    EXPECT_THAT(
        ew.get_exception()->what(),
        HasSubstr("read error awaiting peer close_notify"));
  });

  readCallback_->readEOF();
}

TEST_F(AsyncPSPUpgradeV1Test, TimeoutAwaitingCloseNotify) {
  startAndAwaitPeerSA(std::chrono::milliseconds(100));
  peerSendsSA();
  EXPECT_CALL(mockCallback_, pspError(_)).WillOnce([](auto& ew) {
    EXPECT_THAT(ew.get_exception()->what(), HasSubstr("psp upgrade timeout"));
  });

  evb_.loop();
}

TEST_F(AsyncPSPUpgradeV1Test, CanceledAwaitingCloseNotify) {
  startAndAwaitPeerSA();
  peerSendsSA();
  EXPECT_CALL(mockCallback_, pspError(_)).WillOnce([](auto& ew) {
    EXPECT_THAT(ew.get_exception()->what(), HasSubstr("psp upgrade cancelled"));
  });

  upgrade_.reset();
}

TEST_F(AsyncPSPUpgradeV1Test, TxAssocFails) {
  startAndAwaitPeerSA();
  peerSendsSA();
  EXPECT_CALL(mockKernelPSP_, txAssoc(_, kFd))
      .WillOnce(Return(
          folly::makeSemiFuture<folly::Unit>(
              folly::make_exception_wrapper<std::runtime_error>(
                  "hardware blew up"))));
  EXPECT_CALL(mockCallback_, pspError(_)).WillOnce([](auto& ew) {
    EXPECT_THAT(ew.get_exception()->what(), HasSubstr("psp_tx_assoc failure"));
  });

  endOfTLSCallback_->endOfTLS(&transport_, nullptr);
  evb_.loop();
}

TEST_F(AsyncPSPUpgradeV1Test, TxAssocWaitsForCloseNotify) {
  // The kernel refuses the tx assoc while the peer's close_notify is still in
  // the receive queue, so it must not start before endOfTLS().
  startAndAwaitPeerSA();
  peerSendsSA();
  evb_.loop();

  EXPECT_CALL(mockKernelPSP_, txAssoc(_, kFd))
      .WillOnce(Return(folly::makeSemiFuture(folly::unit)));
  EXPECT_CALL(mockCallback_, pspSuccess(_, _));
  endOfTLSCallback_->endOfTLS(&transport_, nullptr);
  evb_.loop();
}

TEST_F(AsyncPSPUpgradeV1Test, SuccessfulNegotiation) {
  startAndAwaitPeerSA();
  peerSendsSA();
  EXPECT_CALL(mockKernelPSP_, txAssoc(_, kFd))
      .WillOnce([](const auto& sa, int) {
        EXPECT_EQ(sa.spi, 0x11223344);
        EXPECT_EQ(sa.key, makeSA().key);
        return folly::makeSemiFuture(folly::unit);
      });
  // Data the peer sent right after its close_notify must reach the new owner.
  EXPECT_CALL(mockCallback_, pspSuccess(folly::NetworkSocket::fromFd(kFd), _))
      .WillOnce([](auto, std::unique_ptr<folly::IOBuf> postTlsData) {
        ASSERT_NE(postTlsData, nullptr);
        EXPECT_EQ(postTlsData->moveToFbString(), "post tls data");
      });
  // The socket changes owners, so a successful upgrade must not close it.
  EXPECT_CALL(*inner_, closeNow()).Times(0);

  endOfTLSCallback_->endOfTLS(
      &transport_, folly::IOBuf::copyBuffer("post tls data"));
  evb_.loop();
}

} // namespace
