/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

namespace fizz {

template <typename T>
void Sha<T>::hmac(
    folly::ByteRange key,
    const folly::IOBuf& in,
    folly::MutableByteRange out) {
  CHECK_GE(out.size(), T::HashLen);
  folly::ssl::OpenSSLHash::hmac(out, T::HashEngine(), key, in);
}

template <typename T>
void Sha<T>::hash(const folly::IOBuf& in, folly::MutableByteRange out) {
  CHECK_GE(out.size(), T::HashLen);
  folly::ssl::OpenSSLHash::hash(out, T::HashEngine(), in);
}
} // namespace fizz
