/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <boost/variant.hpp>
#include <fizz/protocol/Actions.h>
#include <folly/futures/Future.h>
#include <folly/small_vector.h>

namespace fizz {
namespace server {

class State;

/**
 * A lambda that should be invoked on State so that modification can be applied.
 */
using MutateState = folly::Function<void(State&)>;

struct AttemptVersionFallback {
  std::unique_ptr<folly::IOBuf> clientHello;
};

/**
 * Reports that early data was received and accepted. Application data delivered
 * after ReportEarlyHandshakeSuccess but before ReportHandshakeSuccess was
 * received using the early cipher.
 */
struct ReportEarlyHandshakeSuccess {};

/**
 * Reports that the full handshake has completed successfully.
 */
struct ReportHandshakeSuccess {};

using Action = boost::variant<
    DeliverAppData,
    WriteToSocket,
    ReportHandshakeSuccess,
    ReportEarlyHandshakeSuccess,
    ReportError,
    EndOfData,
    MutateState,
    WaitForData,
    AttemptVersionFallback,
    SecretAvailable>;
using Actions = folly::small_vector<Action, 4>;
using AsyncActions = boost::variant<Actions, folly::Future<Actions>>;

namespace detail {

template <typename... Args>
Actions actions(Args&&... act) {
  Actions acts;
  fizz::detail::addAction(acts, std::forward<Args>(act)...);
  return acts;
}
} // namespace detail
} // namespace server
} // namespace fizz
