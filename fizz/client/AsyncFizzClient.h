/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/client/ClientExtensions.h>
#include <fizz/client/ClientProtocol.h>
#include <fizz/client/EarlyDataRejectionPolicy.h>
#include <fizz/client/FizzClient.h>
#include <fizz/client/FizzClientContext.h>
#include <fizz/protocol/AsyncFizzBase.h>
#include <fizz/protocol/Exporter.h>

namespace fizz {
namespace client {

template <typename SM>
class AsyncFizzClientT : public AsyncFizzBase,
                         private folly::AsyncSocket::ConnectCallback {
 public:
  class HandshakeCallback {
   public:
    virtual ~HandshakeCallback() = default;

    virtual void fizzHandshakeSuccess(AsyncFizzClientT* transport) noexcept = 0;

    virtual void fizzHandshakeError(
        AsyncFizzClientT* transport,
        folly::exception_wrapper ex) noexcept = 0;
  };

  using UniquePtr =
      std::unique_ptr<AsyncFizzClientT, folly::DelayedDestruction::Destructor>;

  /**
   * Creates an AsyncFizzClient using an open socket. Connections are made using
   * connect() APIs taking a HandshakeCallback.
   **/
  AsyncFizzClientT(
      folly::AsyncTransportWrapper::UniquePtr socket,
      std::shared_ptr<const FizzClientContext> fizzContext,
      const std::shared_ptr<ClientExtensions>& extensions = nullptr);

  /**
   * Creates an AsyncFizzClient using an event base. This will open the socket
   *for you when you call the connec() API taking a SocketAddress and
   *ConnectCallback.
   **/
  AsyncFizzClientT(
      folly::EventBase* eventBase,
      std::shared_ptr<const FizzClientContext> fizzContext,
      const std::shared_ptr<ClientExtensions>& extensions = nullptr);

  /**
   * Performs a TLS handshake using the open socket passed into the constructor.
   **/
  virtual void connect(
      HandshakeCallback* callback,
      std::shared_ptr<const CertificateVerifier> verifier,
      folly::Optional<std::string> sni,
      folly::Optional<std::string> pskIdentity,
      std::chrono::milliseconds = std::chrono::milliseconds(0));

  /**
   * Opens a socket to the given address and performs a TLS handshake.
   **/
  virtual void connect(
      const folly::SocketAddress& connectAddr,
      folly::AsyncSocket::ConnectCallback* callback,
      std::shared_ptr<const CertificateVerifier> verifier,
      folly::Optional<std::string> sni,
      folly::Optional<std::string> pskIdentity,
      std::chrono::milliseconds totalTimeout = std::chrono::milliseconds(0),
      std::chrono::milliseconds socketTimeout = std::chrono::milliseconds(0),
      const folly::AsyncSocket::OptionMap& options =
          folly::AsyncSocket::emptyOptionMap,
      const folly::SocketAddress& bindAddr = folly::AsyncSocket::anyAddress());

  /**
   * Variant of the TLS handshake connect() API above that uses the default
   *certificate verifier implementation.
   **/
  virtual void connect(
      HandshakeCallback* callback,
      folly::Optional<std::string> hostname,
      std::chrono::milliseconds = std::chrono::milliseconds(0));

  bool good() const override;
  bool readable() const override;
  bool connecting() const override;
  bool error() const override;

  const Cert* getPeerCertificate() const override;
  const Cert* getSelfCertificate() const override;

  bool isReplaySafe() const override;
  void setReplaySafetyCallback(
      folly::AsyncTransport::ReplaySafetyCallback* callback) override;
  std::string getApplicationProtocol() const noexcept override;

  void close() override;
  void closeWithReset() override;
  void closeNow() override;

  /**
   * Set the policy for dealing with rejected early data.
   *
   * Note that early data must be also be enabled on the FizzClientContext for
   * early data to be used.
   */
  void setEarlyDataRejectionPolicy(EarlyDataRejectionPolicy policy) {
    CHECK(!earlyDataState_);
    earlyDataRejectionPolicy_ = policy;
  }

  /**
   * Internal state access for logging/testing.
   */
  const State& getState() const {
    return state_;
  }

  folly::Optional<CipherSuite> getCipher() const override;

  std::vector<SignatureScheme> getSupportedSigSchemes() const override;

  Buf getEkm(folly::StringPiece label, const Buf& context, uint16_t length)
      const override;

  Buf getEarlyEkm(folly::StringPiece label, const Buf& context, uint16_t length)
      const;

  bool pskResumed() const;

 protected:
  ~AsyncFizzClientT() override = default;
  void writeAppData(
      folly::AsyncTransportWrapper::WriteCallback* callback,
      std::unique_ptr<folly::IOBuf>&& buf,
      folly::WriteFlags flags = folly::WriteFlags::NONE) override;

  void transportError(const folly::AsyncSocketException& ex) override;

  void transportDataAvailable() override;

 private:
  void deliverAllErrors(
      const folly::AsyncSocketException& ex,
      bool closeTransport = true);
  void deliverHandshakeError(folly::exception_wrapper ex);

  void connectErr(const folly::AsyncSocketException& ex) noexcept override;
  void connectSuccess() noexcept override;

  folly::Optional<folly::AsyncSocketException> handleEarlyReject();

  class ActionMoveVisitor : public boost::static_visitor<> {
   public:
    explicit ActionMoveVisitor(AsyncFizzClientT<SM>& client)
        : client_(client) {}

    void operator()(DeliverAppData&);
    void operator()(WriteToSocket&);
    void operator()(ReportEarlyHandshakeSuccess&);
    void operator()(ReportHandshakeSuccess&);
    void operator()(ReportEarlyWriteFailed&);
    void operator()(ReportError&);
    void operator()(WaitForData&);
    void operator()(MutateState&);
    void operator()(NewCachedPsk&);
    void operator()(SecretAvailable&);
    void operator()(EndOfData&);

   private:
    AsyncFizzClientT<SM>& client_;
  };

  folly::Optional<
      boost::variant<HandshakeCallback*, folly::AsyncSocket::ConnectCallback*>>
      callback_;

  std::shared_ptr<const FizzClientContext> fizzContext_;

  std::shared_ptr<ClientExtensions> extensions_;

  folly::Optional<std::string> sni_;

  folly::Optional<std::string> pskIdentity_;

  State state_;

  ActionMoveVisitor visitor_;

  FizzClient<ActionMoveVisitor, SM> fizzClient_;

  struct EarlyDataState {
    // How much data is remaining in max early data size.
    uint32_t remainingEarlyData{0};

    // Early data that has been written so far. Only used with AutomaticResend
    // rejection policy.
    folly::IOBufQueue resendBuffer{folly::IOBufQueue::cacheChainLength()};

    // Writes that we haven't written yet due to exceeding the max early data
    // size.
    std::deque<AppWrite> pendingAppWrites;
  };

  // Only set if we are currently in early data state.
  folly::Optional<EarlyDataState> earlyDataState_;

  EarlyDataRejectionPolicy earlyDataRejectionPolicy_{
      EarlyDataRejectionPolicy::FatalConnectionError};

  folly::AsyncTransport::ReplaySafetyCallback* replaySafetyCallback_{nullptr};

  // Set when using socket connect() API to later pass into the state machine
  std::shared_ptr<const CertificateVerifier> verifier_;
};

using AsyncFizzClient = AsyncFizzClientT<ClientStateMachine>;
} // namespace client
} // namespace fizz

#include <fizz/client/AsyncFizzClient-inl.h>
