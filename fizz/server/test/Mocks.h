/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GMock.h>

#include <fizz/crypto/aead/test/Mocks.h>
#include <fizz/crypto/exchange/test/Mocks.h>
#include <fizz/protocol/test/Mocks.h>
#include <fizz/record/test/Mocks.h>
#include <fizz/server/AsyncFizzServer.h>
#include <fizz/server/AsyncSelfCert.h>
#include <fizz/server/CookieCipher.h>
#include <fizz/server/ReplayCache.h>
#include <fizz/server/ServerExtensions.h>
#include <fizz/server/ServerProtocol.h>

namespace fizz {
namespace server {
namespace test {

/* using override */
using namespace testing;
/* using override */
using namespace fizz::test;

class MockServerStateMachine : public ServerStateMachine {
 public:
  MOCK_METHOD4(
      _processAccept,
      folly::Optional<AsyncActions>(
          const State&,
          folly::Executor*,
          std::shared_ptr<const FizzServerContext> context,
          const std::shared_ptr<ServerExtensions>& extensions));
  AsyncActions processAccept(
      const State& state,
      folly::Executor* executor,
      std::shared_ptr<const FizzServerContext> context,
      const std::shared_ptr<ServerExtensions>& extensions) override {
    return *_processAccept(state, executor, std::move(context), extensions);
  }

  MOCK_METHOD2(
      _processSocketData,
      folly::Optional<AsyncActions>(const State&, folly::IOBufQueue&));
  AsyncActions processSocketData(const State& state, folly::IOBufQueue& queue)
      override {
    return *_processSocketData(state, queue);
  }

  MOCK_METHOD2(
      _processWriteNewSessionTicket,
      folly::Optional<AsyncActions>(const State&, WriteNewSessionTicket&));
  AsyncActions processWriteNewSessionTicket(
      const State& state,
      WriteNewSessionTicket write) override {
    return *_processWriteNewSessionTicket(state, write);
  }

  MOCK_METHOD2(
      _processAppWrite,
      folly::Optional<AsyncActions>(const State&, AppWrite&));
  AsyncActions processAppWrite(const State& state, AppWrite appWrite) override {
    return *_processAppWrite(state, appWrite);
  }

  MOCK_METHOD2(
      _processEarlyAppWrite,
      folly::Optional<AsyncActions>(const State&, EarlyAppWrite&));
  AsyncActions processEarlyAppWrite(const State& state, EarlyAppWrite appWrite)
      override {
    return *_processEarlyAppWrite(state, appWrite);
  }

  MOCK_METHOD1(_processAppClose, folly::Optional<Actions>(const State&));
  Actions processAppClose(const State& state) override {
    return *_processAppClose(state);
  }

  MOCK_METHOD1(
      _processAppCloseImmediate,
      folly::Optional<Actions>(const State&));
  Actions processAppCloseImmediate(const State& state) override {
    return *_processAppCloseImmediate(state);
  }
};

class MockTicketCipher : public TicketCipher {
 public:
  MOCK_CONST_METHOD1(
      _encrypt,
      folly::Future<folly::Optional<std::pair<Buf, std::chrono::seconds>>>(
          ResumptionState&));
  folly::Future<folly::Optional<std::pair<Buf, std::chrono::seconds>>> encrypt(
      ResumptionState resState) const override {
    return _encrypt(resState);
  }

  MOCK_CONST_METHOD1(
      _decrypt,
      folly::Future<std::pair<PskType, folly::Optional<ResumptionState>>>(
          std::unique_ptr<folly::IOBuf>& encryptedTicket));
  folly::Future<std::pair<PskType, folly::Optional<ResumptionState>>> decrypt(
      std::unique_ptr<folly::IOBuf> encryptedTicket) const override {
    return _decrypt(encryptedTicket);
  }

  void setDefaults(
      std::chrono::system_clock::time_point ticketIssued =
          std::chrono::system_clock::now()) {
    ON_CALL(*this, _decrypt(_))
        .WillByDefault(InvokeWithoutArgs([ticketIssued]() {
          ResumptionState res;
          res.version = ProtocolVersion::tls_1_3;
          res.cipher = CipherSuite::TLS_AES_128_GCM_SHA256;
          res.resumptionSecret = folly::IOBuf::copyBuffer("resumesecret");
          res.alpn = "h2";
          res.ticketAgeAdd = 0;
          res.ticketIssueTime = ticketIssued;
          res.handshakeTime = ticketIssued;
          return std::make_pair(PskType::Resumption, std::move(res));
        }));
    ON_CALL(*this, _encrypt(_)).WillByDefault(InvokeWithoutArgs([]() {
      return std::make_pair(
          folly::IOBuf::copyBuffer("ticket"), std::chrono::seconds(100));
    }));
  }
};

class MockCookieCipher : public CookieCipher {
 public:
  MOCK_CONST_METHOD1(_decrypt, folly::Optional<CookieState>(Buf&));
  folly::Optional<CookieState> decrypt(Buf cookie) const override {
    return _decrypt(cookie);
  }
};

template <typename SM>
class MockHandshakeCallbackT : public AsyncFizzServerT<SM>::HandshakeCallback {
 public:
  MOCK_METHOD0(_fizzHandshakeSuccess, void());
  void fizzHandshakeSuccess(AsyncFizzServerT<SM>*) noexcept override {
    _fizzHandshakeSuccess();
  }

  MOCK_METHOD1(_fizzHandshakeError, void(folly::exception_wrapper));
  void fizzHandshakeError(
      AsyncFizzServerT<SM>*,
      folly::exception_wrapper ew) noexcept override {
    _fizzHandshakeError(std::move(ew));
  }

  MOCK_METHOD1(
      _fizzHandshakeAttemptFallback,
      void(std::unique_ptr<folly::IOBuf>&));
  void fizzHandshakeAttemptFallback(
      std::unique_ptr<folly::IOBuf> clientHello) override {
    return _fizzHandshakeAttemptFallback(clientHello);
  }
};

using MockHandshakeCallback = MockHandshakeCallbackT<ServerStateMachine>;

template <typename SM>
class MockAsyncFizzServerT : public AsyncFizzServerT<SM> {
 public:
  MockAsyncFizzServerT(
      folly::AsyncTransportWrapper::UniquePtr socket,
      const std::shared_ptr<FizzServerContext>& fizzContext)
      : AsyncFizzServerT<SM>(std::move(socket), fizzContext) {}

  using UniquePtr = std::
      unique_ptr<MockAsyncFizzServerT, folly::DelayedDestruction::Destructor>;

  MOCK_CONST_METHOD3(getEkm, Buf(folly::StringPiece, const Buf&, uint16_t));
};

using MockAsyncFizzServer = MockAsyncFizzServerT<ServerStateMachine>;

class MockCertManager : public CertManager {
 public:
  MOCK_CONST_METHOD4(
      getCert,
      CertMatch(
          const folly::Optional<std::string>& sni,
          const std::vector<SignatureScheme>& supportedSigSchemes,
          const std::vector<SignatureScheme>& peerSigSchemes,
          const std::vector<Extension>& peerExtensions));
  MOCK_CONST_METHOD1(
      getCert,
      std::shared_ptr<SelfCert>(const std::string& identity));
};

class MockServerExtensions : public ServerExtensions {
 public:
  MOCK_METHOD1(getExtensions, std::vector<Extension>(const ClientHello& chlo));
};

class MockReplayCache : public ReplayCache {
 public:
  MOCK_METHOD1(check, folly::Future<ReplayCacheResult>(folly::ByteRange));
};

class MockAppTokenValidator : public AppTokenValidator {
 public:
  MOCK_CONST_METHOD1(validate, bool(const ResumptionState&));
};

class MockAsyncSelfCert : public AsyncSelfCert {
 public:
  MOCK_CONST_METHOD0(getIdentity, std::string());
  MOCK_CONST_METHOD0(getAltIdentities, std::vector<std::string>());
  MOCK_CONST_METHOD0(getSigSchemes, std::vector<SignatureScheme>());

  MOCK_CONST_METHOD1(_getCertMessage, CertificateMsg(Buf&));
  CertificateMsg getCertMessage(Buf buf) const override {
    return _getCertMessage(buf);
  }
  MOCK_CONST_METHOD1(
      getCompressedCert,
      CompressedCertificate(CertificateCompressionAlgorithm));

  MOCK_CONST_METHOD3(
      sign,
      Buf(SignatureScheme scheme,
          CertificateVerifyContext context,
          folly::ByteRange toBeSigned));
  MOCK_CONST_METHOD0(getX509, folly::ssl::X509UniquePtr());
  MOCK_CONST_METHOD3(
      signFuture,
      folly::Future<folly::Optional<Buf>>(
          SignatureScheme scheme,
          CertificateVerifyContext context,
          folly::ByteRange toBeSigned));
};
} // namespace test
} // namespace server
} // namespace fizz
