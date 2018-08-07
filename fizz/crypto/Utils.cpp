/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/crypto/Utils.h>

#include <sodium.h>

namespace fizz {

bool CryptoUtils::equal(folly::ByteRange a, folly::ByteRange b) {
  if (a.size() != b.size()) {
    return false;
  }
  return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

void CryptoUtils::clean(folly::MutableByteRange range) {
  sodium_memzero(range.data(), range.size());
}
} // namespace fizz
