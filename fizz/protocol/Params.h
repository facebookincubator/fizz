/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <boost/variant.hpp>
#include <fizz/client/ClientExtensions.h>
#include <fizz/client/PskCache.h>
#include <fizz/protocol/Events.h>
#include <fizz/record/Types.h>
#include <folly/io/IOBuf.h>
#include <folly/io/async/AsyncTransport.h>

namespace fizz {

class CertificateVerifier;
class ServerExtensions;

namespace server {
class FizzServerContext;
}

namespace client {
class FizzClientContext;
}

struct Accept : EventType<Event::Accept> {
  folly::Executor* executor;
  std::shared_ptr<const server::FizzServerContext> context;
  std::shared_ptr<ServerExtensions> extensions;
};

struct Connect : EventType<Event::Connect> {
  std::shared_ptr<const client::FizzClientContext> context;
  std::shared_ptr<const CertificateVerifier> verifier;
  folly::Optional<std::string> sni;
  folly::Optional<client::CachedPsk> cachedPsk;
  std::shared_ptr<ClientExtensions> extensions;
};

struct EarlyAppWrite : EventType<Event::EarlyAppWrite> {
  folly::AsyncTransportWrapper::WriteCallback* callback{nullptr};
  std::unique_ptr<folly::IOBuf> data;
  folly::WriteFlags flags;
};

struct AppWrite : EventType<Event::AppWrite> {
  folly::AsyncTransportWrapper::WriteCallback* callback{nullptr};
  std::unique_ptr<folly::IOBuf> data;
  folly::WriteFlags flags;
};

struct AppData : EventType<Event::AppData> {
  std::unique_ptr<folly::IOBuf> data;

  explicit AppData(std::unique_ptr<folly::IOBuf> buf) : data(std::move(buf)) {}
};

struct WriteNewSessionTicket : EventType<Event::WriteNewSessionTicket> {
  Buf appToken;
};

/**
 * Parameters for each event that will be processed by the state machine.
 */
using Param = boost::variant<
    ClientHello,
    ServerHello,
    EndOfEarlyData,
    HelloRetryRequest,
    EncryptedExtensions,
    CertificateRequest,
    CompressedCertificate,
    CertificateMsg,
    CertificateVerify,
    Finished,
    NewSessionTicket,
    KeyUpdate,
    Alert,
    CloseNotify,
    Accept,
    Connect,
    AppData,
    AppWrite,
    EarlyAppWrite,
    WriteNewSessionTicket>;

class EventVisitor : public boost::static_visitor<Event> {
 public:
  template <class T>
  Event operator()(const T&) const {
    return T::event;
  }
};

// App closes bypass the state machine so aren't in the Param variant.
struct AppClose {
  enum ClosePolicy { IMMEDIATE, WAIT };

  /*implicit */ constexpr AppClose(ClosePolicy pol) : policy(pol) {}

  ClosePolicy policy;
};

} // namespace fizz
