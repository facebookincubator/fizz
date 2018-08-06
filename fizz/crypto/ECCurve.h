/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <openssl/evp.h>

namespace fizz {

struct P256 {
  static const int curveNid{NID_X9_62_prime256v1};
};

struct P384 {
  static const int curveNid{NID_secp384r1};
};

struct P521 {
  static const int curveNid{NID_secp521r1};
};

} // namespace fizz
