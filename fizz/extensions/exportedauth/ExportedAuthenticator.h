/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/protocol/Certificate.h>
#include <fizz/protocol/Exporter.h>
#include <fizz/protocol/Protocol.h>
#include <fizz/record/Types.h>

namespace fizz {

class ExportedAuthenticator {
 public:
  static Buf getAuthenticatorRequest(
      Buf certificateRequestContext,
      std::vector<fizz::Extension> extensions);
};

} // namespace fizz
