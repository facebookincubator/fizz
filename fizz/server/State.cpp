/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/server/State.h>


namespace fizz {
namespace server {

folly::StringPiece toString(StateEnum state) {
  switch (state) {
    case StateEnum::Uninitialized:
      return "Uninitialized";
    case StateEnum::ExpectingClientHello:
      return "ExpectingClientHello";
    case StateEnum::ExpectingCertificate:
      return "ExpectingCertificate";
    case StateEnum::AcceptingEarlyData:
      return "AcceptingEarlyData";
    case StateEnum::ExpectingCertificateVerify:
      return "ExpectingCertificateVerify";
    case StateEnum::ExpectingFinished:
      return "ExpectingFinished";
    case StateEnum::AcceptingData:
      return "AcceptingData";
    case StateEnum::ExpectingCloseNotify:
      return "ExpectingCloseNotify";
    case StateEnum::Closed:
      return "Closed";
    case StateEnum::Error:
      return "Error";
    case StateEnum::NUM_STATES:
      return "Invalid state NUM_STATES";
  }
  return "Invalid state";
}
} // namespace server
} // namespace fizz
