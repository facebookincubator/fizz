/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include <fizz/experimental/ktls/AsyncKTLSSocket.h>
#include <fizz/protocol/AsyncFizzBase.h>
#include <folly/Expected.h>
#include <glog/logging.h>

namespace fizz {
/**
 * fizz::tryConvertKTLS attempts to convert a fizz::AsyncFizzBase socket into
 * an instance of fizz::AsyncKTLSSocket
 *
 * This can only be safely called within a fizzHandshakeSuc() callback, where
 * the socket uses `setHandshakeRecordAlignedReads(true)`, before any
 * application writes are made to the fizz socket.
 *
 * During the conversion process:
 * * The new socket's EventBase is set to the old socket's EventBase.
 * * The new socket's read callback is set to the old socket's read callback, if
 *   set.
 * * Any pending writes on the old socket fail with writeErr().
 *
 * @param fizzSock         Either a fizz::client::AsyncFizzClient or
 *                         fizz::server::AsyncFizzServer reference.
 *
 *                         If this function succeeds, then fizzSock will no
 *                         longer be valid -- it's underlying file descriptor
 *                         will have been moved.
 *
 * @return An Expected result. On success, this returns unique ownership of an
 * AsyncKTLSSocket instance that uses the file descriptor of |fizzSock|. On
 * failure, returns the exception. On failure, |fizzSock| will still be valid;
 * it's file descriptor remains attached, and future I/O operations on
 * |fizzSock| are allowed.
 *
 */
template <class FizzSocket>
folly::Expected<AsyncKTLSSocket::UniquePtr, folly::exception_wrapper>
tryConvertKTLS(FizzSocket& fizzSock) {
#if defined(__linux__) && !defined(__ANDROID__)
  static_assert(
      std::is_base_of<AsyncFizzBase, FizzSocket>::value,
      "FizzSocket must be derived from AsyncFizzBase");

  if (!fizzSock.good() || fizzSock.connecting()) {
    return folly::makeUnexpected<folly::exception_wrapper>(
        std::runtime_error("convertKTLS failed: fizz socket in bad state"));
  }

  // TODO: This will probably grab the wrong transport if there are multiple
  // transports in a chain that implement AsyncSocket.
  //
  // `getUnderlyingTransport` is the wrong function to use, since it will
  // recursively call `getUnderlyingTransport` on wrapped transports.
  //
  // `getWrappedTransport` is somewhat better, but it will not be able to
  // handle "middleware" transports that do not change the I/O path.
  //
  // What we probably want is to introduce an method on AsyncTransport, e.g.
  //   auto AsyncTransport::getNetworkSocketSink() -> Optional<NetworkSocket>
  // so that middleware transports can "pass through" the NetworkSocket, but
  // transport implementations that act as an I/O sink do not propagate this.
  auto sock = fizzSock.template getUnderlyingTransport<folly::AsyncSocket>();
  if (!sock) {
    return folly::makeUnexpected<folly::exception_wrapper>(std::runtime_error(
        "convertKTLS failed: underlying transport does not have associated socket"));
  }

  // TODO: Need to check that there aren't any AsyncSocket queued writes that
  // were not yet accepted by the kernel (or AsyncFizzBase queued writes)
  // since we are going to destroy the underlying socket.

  // if the socket is good() and we aren't connecting, then this implies the
  // handshake has already completed, so the following values must be set.
  const auto& state = fizzSock.getState();
  DCHECK(state.cipher().has_value());
  DCHECK(state.readRecordLayer());
  DCHECK(state.writeRecordLayer());

  auto ciphersuite = *state.cipher();
  auto rstate = (*state.readRecordLayer()).getRecordLayerState();
  auto wstate = (*state.writeRecordLayer()).getRecordLayerState();

  auto evb = fizzSock.getEventBase();

  auto rx = KTLSDirectionalCryptoParams<TrafficDirection::Receive>(
      KTLSCryptoParams::fromRecordState(ciphersuite, rstate));
  auto tx = KTLSDirectionalCryptoParams<TrafficDirection::Transmit>(
      KTLSCryptoParams::fromRecordState(ciphersuite, wstate));

  auto result =
      KTLSNetworkSocket::tryEnableKTLS(sock->getNetworkSocket(), rx, tx);
  if (!result) {
    return folly::makeUnexpected<folly::exception_wrapper>(
        std::move(result).error());
  }

  auto readCb = fizzSock.getReadCallback();
  fizzSock.setReadCB(nullptr);

  (void)sock->detachNetworkSocket();
  AsyncKTLSSocket::UniquePtr ret;
  // TODO: extract key scheduler and psk cache and use it as tls callback.
  ret.reset(new AsyncKTLSSocket(evb, result.value(), nullptr));
  ret->setReadCB(readCb);
  return ret;
#else
  return folly::makeUnexpected<folly::exception_wrapper>(
      std::runtime_error("ktls statically not supported on platform"));
#endif
}
} // namespace fizz
