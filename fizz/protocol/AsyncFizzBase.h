/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/protocol/KeyScheduler.h>
#include <fizz/record/Types.h>
#include <folly/io/IOBufQueue.h>
#include <folly/io/async/AsyncSocket.h>
#include <folly/io/async/WriteChainAsyncTransportWrapper.h>

namespace fizz {

using Cert = folly::AsyncTransportCertificate;

/**
 * This class is a wrapper around AsyncTransportWrapper to handle most app level
 * interactions so that the derived client and server classes
 */
class AsyncFizzBase : public folly::WriteChainAsyncTransportWrapper<
                          folly::AsyncTransportWrapper>,
                      protected folly::AsyncTransportWrapper::WriteCallback,
                      protected folly::AsyncTransportWrapper::ReadCallback {
 public:
  using UniquePtr =
      std::unique_ptr<AsyncFizzBase, folly::DelayedDestruction::Destructor>;
  using ReadCallback = folly::AsyncTransportWrapper::ReadCallback;

  class HandshakeTimeout : public folly::AsyncTimeout {
   public:
    HandshakeTimeout(AsyncFizzBase& transport, folly::EventBase* eventBase)
        : folly::AsyncTimeout(eventBase), transport_(transport) {}

    ~HandshakeTimeout() override = default;

    void timeoutExpired() noexcept override {
      transport_.handshakeTimeoutExpired();
    }

   private:
    AsyncFizzBase& transport_;
  };

  class SecretCallback {
   public:
    virtual ~SecretCallback() = default;
    /**
     * Each of the below is called when the corresponding secret is received.
     */
    virtual void externalPskBinderAvailable(
        const std::vector<uint8_t>&) noexcept {}
    virtual void resumptionPskBinderAvailable(
        const std::vector<uint8_t>&) noexcept {}
    virtual void earlyExporterSecretAvailable(
        const std::vector<uint8_t>&) noexcept {}
    virtual void clientEarlyTrafficSecretAvailable(
        const std::vector<uint8_t>&) noexcept {}
    virtual void clientHandshakeTrafficSecretAvailable(
        const std::vector<uint8_t>&) noexcept {}
    virtual void serverHandshakeTrafficSecretAvailable(
        const std::vector<uint8_t>&) noexcept {}
    virtual void exporterMasterSecretAvailable(
        const std::vector<uint8_t>&) noexcept {}
    virtual void resumptionMasterSecretAvailable(
        const std::vector<uint8_t>&) noexcept {}
    virtual void clientAppTrafficSecretAvailable(
        const std::vector<uint8_t>&) noexcept {}
    virtual void serverAppTrafficSecretAvailable(
        const std::vector<uint8_t>&) noexcept {}
  };

  explicit AsyncFizzBase(folly::AsyncTransportWrapper::UniquePtr transport);

  ~AsyncFizzBase() override;

  /**
   * App level information for reading/writing app data.
   */
  ReadCallback* getReadCallback() const override;
  void setReadCB(ReadCallback* callback) override;
  void writeChain(
      folly::AsyncTransportWrapper::WriteCallback* callback,
      std::unique_ptr<folly::IOBuf>&& buf,
      folly::WriteFlags flags = folly::WriteFlags::NONE) override;

  /**
   * App data usage accounting.
   */
  size_t getAppBytesWritten() const override;
  size_t getAppBytesReceived() const override;

  /**
   * Information about the current transport state.
   * To be implemented by derived classes.
   */
  bool good() const override = 0;
  bool readable() const override = 0;
  bool connecting() const override = 0;
  bool error() const override = 0;

  /**
   * Get the certificates in fizz::Cert form.
   */
  const Cert* getPeerCertificate() const override = 0;

  const Cert* getSelfCertificate() const override = 0;

  bool isReplaySafe() const override = 0;
  void setReplaySafetyCallback(
      folly::AsyncTransport::ReplaySafetyCallback* callback) override = 0;
  std::string getApplicationProtocol() const noexcept override = 0;

  /**
   * Get the CipherSuite negotiated in this transport.
   */
  virtual folly::Optional<CipherSuite> getCipher() const = 0;

  /**
   * Get the supported signature schemes in this transport.
   */
  virtual std::vector<SignatureScheme> getSupportedSigSchemes() const = 0;

  /**
   * Get the exported material.
   */
  virtual Buf getEkm(
      folly::StringPiece label,
      const Buf& context,
      uint16_t length) const = 0;

  /**
   * Clean up transport on destruction
   */
  void destroy() override;

  /**
   * Identify the transport as Fizz.
   */
  std::string getSecurityProtocol() const override {
    return "Fizz";
  }

  /**
   * EventBase operations.
   */
  void attachTimeoutManager(folly::TimeoutManager* manager) {
    handshakeTimeout_.attachTimeoutManager(manager);
  }
  void detachTimeoutManager() {
    handshakeTimeout_.detachTimeoutManager();
  }
  void attachEventBase(folly::EventBase* eventBase) override {
    handshakeTimeout_.attachEventBase(eventBase);
    transport_->attachEventBase(eventBase);
    // we want to avoid setting a read cb on a bad transport (i.e. closed or
    // disconnected) unless we have a read callback we can pass the errors to.
    if (transport_->good() || readCallback_) {
      startTransportReads();
    }
  }
  void detachEventBase() override {
    handshakeTimeout_.detachEventBase();
    transport_->setReadCB(nullptr);
    transport_->detachEventBase();
  }
  bool isDetachable() const override {
    return !handshakeTimeout_.isScheduled() && transport_->isDetachable();
  }

  void setSecretCallback(SecretCallback* cb) {
    secretCallback_ = cb;
  }

  SecretCallback* getSecretCallback() {
    return secretCallback_;
  }

  /**
   * Behavior tunables
   */

  /**
   * setCloseTransportOnCloseNotify() defines the behavior taken when the remote
   * peer sends us a close_notify alert, signaling their intention to tear
   * down the TLS session.
   *
   * By default, upon receipt of a close_notify alert, we will immediately
   * tear down the transport without responding with our own close_notify.
   */
  void setCloseTransportOnCloseNotify(bool flag) {
    closeTransportOnCloseNotify_ = flag;
  }

  bool closeTransportOnCloseNotify() const {
    return closeTransportOnCloseNotify_;
  }

  /*
   * Gets the client random associated with this connection. The CR can be
   * used as a transport agnostic identifier (for instance, for NSS keylogging)
   */
  virtual folly::Optional<Random> getClientRandom() const = 0;

 protected:
  /**
   * Start reading raw data from the transport.
   */
  virtual void startTransportReads();

  /**
   * Interface for the derived class to schedule a handshake timeout.
   *
   * transportError() will be called if the timeout fires before it is
   * cancelled.
   */
  virtual void startHandshakeTimeout(std::chrono::milliseconds);
  virtual void cancelHandshakeTimeout();

  /**
   * Interfaces for the derived class to interact with the app level read
   * callback.
   */
  virtual void deliverAppData(std::unique_ptr<folly::IOBuf> buf);
  virtual void deliverError(
      const folly::AsyncSocketException& ex,
      bool closeTransport = true);

  /**
   * Interface for the derived class to implement to receive app data from the
   * app layer.
   */
  virtual void writeAppData(
      folly::AsyncTransportWrapper::WriteCallback* callback,
      std::unique_ptr<folly::IOBuf>&& buf,
      folly::WriteFlags flags = folly::WriteFlags::NONE) = 0;

  /**
   * Alert the derived class that a transport error occured.
   */
  virtual void transportError(const folly::AsyncSocketException& ex) = 0;
  /**
   * Alert the derived class that additional data is available in
   * transportReadBuf_.
   */
  virtual void transportDataAvailable() = 0;

  /**
   * Allows the derived class to give a derived secret to the secret callback.
   */
  virtual void secretAvailable(const DerivedSecret& secret) noexcept;

  folly::IOBufQueue transportReadBuf_{folly::IOBufQueue::cacheChainLength()};

 private:
  class QueuedWriteRequest
      : private folly::AsyncTransportWrapper::WriteCallback {
   public:
    QueuedWriteRequest(
        AsyncFizzBase* base,
        folly::AsyncTransportWrapper::WriteCallback* callback,
        std::unique_ptr<folly::IOBuf> data,
        folly::WriteFlags flags);

    void startWriting();

    void append(QueuedWriteRequest* request);

    void unlinkFromBase();

   private:
    void writeSuccess() noexcept override;

    void writeErr(size_t, const folly::AsyncSocketException&) noexcept override;

    QueuedWriteRequest* deliverSingleWriteErr(
        const folly::AsyncSocketException&);

    void advanceOnBase();

    AsyncFizzBase* asyncFizzBase_;
    folly::AsyncTransportWrapper::WriteCallback* callback_;
    folly::IOBufQueue data_{folly::IOBufQueue::cacheChainLength()};
    folly::WriteFlags flags_;

    size_t dataWritten_{0};

    QueuedWriteRequest* next_{nullptr};
  };

  /**
   * ReadCallback implementation.
   */
  void getReadBuffer(void** bufReturn, size_t* lenReturn) override;
  void readDataAvailable(size_t len) noexcept override;
  bool isBufferMovable() noexcept override;
  void readBufferAvailable(
      std::unique_ptr<folly::IOBuf> data) noexcept override;
  void readEOF() noexcept override;
  void readErr(const folly::AsyncSocketException& ex) noexcept override;

  /**
   * WriteCallback implementation, for use with handshake messages.
   */
  void writeSuccess() noexcept override;
  void writeErr(
      size_t bytesWritten,
      const folly::AsyncSocketException& ex) noexcept override;

  void checkBufLen();

  void handshakeTimeoutExpired() noexcept;

  ReadCallback* readCallback_{nullptr};
  std::unique_ptr<folly::IOBuf> appDataBuf_;

  size_t appBytesWritten_{0};
  size_t appBytesReceived_{0};

  QueuedWriteRequest* tailWriteRequest_{nullptr};

  HandshakeTimeout handshakeTimeout_;

  bool closeTransportOnCloseNotify_{true};
  SecretCallback* secretCallback_{nullptr};
};
} // namespace fizz
