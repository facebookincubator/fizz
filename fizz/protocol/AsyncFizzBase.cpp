/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/protocol/AsyncFizzBase.h>

#include <folly/Conv.h>
#include <folly/io/Cursor.h>

namespace fizz {

using folly::AsyncSocketException;

/**
 * Min and max read buffer sizes when using non-mo
 */
static const uint32_t kMinReadSize = 1460;
static const uint32_t kMaxReadSize = 4000;

/**
 * Buffer size above which we should unset our read callback to apply back
 * pressure on the transport.
 */
static const uint32_t kMaxBufSize = 64 * 1024;

AsyncFizzBase::AsyncFizzBase(folly::AsyncTransportWrapper::UniquePtr transport)
    : folly::WriteChainAsyncTransportWrapper<folly::AsyncTransportWrapper>(
          std::move(transport)),
      handshakeTimeout_(*this, transport_->getEventBase()) {}

AsyncFizzBase::~AsyncFizzBase() {
  transport_->setReadCB(nullptr);
}

void AsyncFizzBase::destroy() {
  transport_->closeNow();
  transport_->setReadCB(nullptr);
  DelayedDestruction::destroy();
}

AsyncFizzBase::ReadCallback* AsyncFizzBase::getReadCallback() const {
  return readCallback_;
}

void AsyncFizzBase::setReadCB(AsyncFizzBase::ReadCallback* callback) {
  readCallback_ = callback;

  if (readCallback_) {
    if (appDataBuf_) {
      deliverAppData(nullptr);
    }

    if (!good()) {
      AsyncSocketException ex(
          AsyncSocketException::NOT_OPEN,
          "setReadCB() called with transport in bad state");
      deliverError(ex);
    } else {
      // The read callback may have been unset earlier if our buffer was full.
      startTransportReads();
    }
  }
}

void AsyncFizzBase::writeChain(
    folly::AsyncTransportWrapper::WriteCallback* callback,
    std::unique_ptr<folly::IOBuf>&& buf,
    folly::WriteFlags flags) {
  appBytesWritten_ += buf->computeChainDataLength();

  // TODO: break up buf into multiple records

  writeAppData(callback, std::move(buf), flags);
}

size_t AsyncFizzBase::getAppBytesWritten() const {
  return appBytesWritten_;
}

size_t AsyncFizzBase::getAppBytesReceived() const {
  return appBytesReceived_;
}

void AsyncFizzBase::startTransportReads() {
  transport_->setReadCB(this);
}

void AsyncFizzBase::startHandshakeTimeout(std::chrono::milliseconds timeout) {
  handshakeTimeout_.scheduleTimeout(timeout);
}

void AsyncFizzBase::cancelHandshakeTimeout() {
  handshakeTimeout_.cancelTimeout();
}

void AsyncFizzBase::deliverAppData(std::unique_ptr<folly::IOBuf> data) {
  if (data) {
    appBytesReceived_ += data->computeChainDataLength();
  }

  if (appDataBuf_) {
    if (data) {
      appDataBuf_->prependChain(std::move(data));
    }
    data = std::move(appDataBuf_);
  }

  if (readCallback_ && data) {
    if (readCallback_->isBufferMovable()) {
      return readCallback_->readBufferAvailable(std::move(data));
    } else {
      folly::io::Cursor cursor(data.get());
      size_t available = 0;
      while ((available = cursor.totalLength()) != 0 && readCallback_) {
        void* buf = nullptr;
        size_t buflen = 0;
        try {
          readCallback_->getReadBuffer(&buf, &buflen);
        } catch (const AsyncSocketException& ase) {
          return deliverError(ase);
        } catch (const std::exception& e) {
          AsyncSocketException ase(
              AsyncSocketException::BAD_ARGS,
              folly::to<std::string>("getReadBuffer() threw ", e.what()));
          return deliverError(ase);
        } catch (...) {
          AsyncSocketException ase(
              AsyncSocketException::BAD_ARGS,
              "getReadBuffer() threw unknown exception");
          return deliverError(ase);
        }
        if (buflen == 0 || buf == nullptr) {
          AsyncSocketException ase(
              AsyncSocketException::BAD_ARGS,
              "getReadBuffer() returned empty buffer");
          return deliverError(ase);
        }

        size_t bytesToRead = std::min(buflen, available);
        cursor.pull(buf, bytesToRead);
        readCallback_->readDataAvailable(bytesToRead);
      }
      if (available != 0) {
        cursor.clone(appDataBuf_, available);
      }
    }
  } else if (data) {
    appDataBuf_ = std::move(data);
  }

  checkBufLen();
}

void AsyncFizzBase::deliverError(
    const AsyncSocketException& ex,
    bool closeTransport) {
  DelayedDestruction::DestructorGuard dg(this);

  if (readCallback_) {
    auto readCallback = readCallback_;
    readCallback_ = nullptr;
    if (ex.getType() == AsyncSocketException::END_OF_FILE) {
      readCallback->readEOF();
    } else {
      readCallback->readErr(ex);
    }
  }
  if (closeTransport) {
    transport_->close();
  }
}

void AsyncFizzBase::getReadBuffer(void** bufReturn, size_t* lenReturn) {
  std::pair<void*, uint32_t> readSpace =
      transportReadBuf_.preallocate(kMinReadSize, kMaxReadSize);
  *bufReturn = readSpace.first;
  *lenReturn = readSpace.second;
}

void AsyncFizzBase::readDataAvailable(size_t len) noexcept {
  DelayedDestruction::DestructorGuard dg(this);

  transportReadBuf_.postallocate(len);
  transportDataAvailable();
  checkBufLen();
}

bool AsyncFizzBase::isBufferMovable() noexcept {
  return true;
}

void AsyncFizzBase::readBufferAvailable(
    std::unique_ptr<folly::IOBuf> data) noexcept {
  DelayedDestruction::DestructorGuard dg(this);

  transportReadBuf_.append(std::move(data));
  transportDataAvailable();
  checkBufLen();
}

void AsyncFizzBase::readEOF() noexcept {
  AsyncSocketException eof(AsyncSocketException::END_OF_FILE, "readEOF()");
  transportError(eof);
}

void AsyncFizzBase::readErr(const folly::AsyncSocketException& ex) noexcept {
  transportError(ex);
}

void AsyncFizzBase::writeSuccess() noexcept {}

void AsyncFizzBase::writeErr(
    size_t /* bytesWritten */,
    const folly::AsyncSocketException& ex) noexcept {
  transportError(ex);
}

void AsyncFizzBase::checkBufLen() {
  if (!readCallback_ &&
      (transportReadBuf_.chainLength() >= kMaxBufSize ||
       (appDataBuf_ && appDataBuf_->computeChainDataLength() >= kMaxBufSize))) {
    transport_->setReadCB(nullptr);
  }
}

void AsyncFizzBase::handshakeTimeoutExpired() noexcept {
  AsyncSocketException eof(
      AsyncSocketException::TIMED_OUT, "handshake timeout expired");
  transportError(eof);
}

// The below maps the secret type to the appropriate secret callback function.
namespace {
class SecretVisitor : public boost::static_visitor<> {
 public:
  explicit SecretVisitor(
      AsyncFizzBase::SecretCallback* cb,
      const std::vector<uint8_t>& secretBuf)
      : callback_(cb), secretBuf_(secretBuf) {}
  void operator()(const EarlySecrets& secret) {
    switch (secret) {
      case EarlySecrets::ExternalPskBinder:
        callback_->externalPskBinderAvailable(secretBuf_);
        return;
      case EarlySecrets::ResumptionPskBinder:
        callback_->resumptionPskBinderAvailable(secretBuf_);
        return;
      case EarlySecrets::ClientEarlyTraffic:
        callback_->clientEarlyTrafficSecretAvailable(secretBuf_);
        return;
      case EarlySecrets::EarlyExporter:
        callback_->earlyExporterSecretAvailable(secretBuf_);
        return;
    }
  }
  void operator()(const HandshakeSecrets& secret) {
    switch (secret) {
      case HandshakeSecrets::ClientHandshakeTraffic:
        callback_->clientHandshakeTrafficSecretAvailable(secretBuf_);
        return;
      case HandshakeSecrets::ServerHandshakeTraffic:
        callback_->serverHandshakeTrafficSecretAvailable(secretBuf_);
        return;
    }
  }
  void operator()(const MasterSecrets& secret) {
    switch (secret) {
      case MasterSecrets::ExporterMaster:
        callback_->exporterMasterSecretAvailable(secretBuf_);
        return;
      case MasterSecrets::ResumptionMaster:
        callback_->resumptionMasterSecretAvailable(secretBuf_);
        return;
    }
  }
  void operator()(const AppTrafficSecrets& secret) {
    switch (secret) {
      case AppTrafficSecrets::ClientAppTraffic:
        callback_->clientAppTrafficSecretAvailable(secretBuf_);
        return;
      case AppTrafficSecrets::ServerAppTraffic:
        callback_->serverAppTrafficSecretAvailable(secretBuf_);
        return;
    }
  }

 private:
  AsyncFizzBase::SecretCallback* callback_;
  const std::vector<uint8_t>& secretBuf_;
};
} // namespace

void AsyncFizzBase::secretAvailable(const DerivedSecret& secret) noexcept {
  if (secretCallback_) {
    SecretVisitor visitor(secretCallback_, secret.secret);
    boost::apply_visitor(visitor, secret.type);
  }
}
} // namespace fizz
