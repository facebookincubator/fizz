/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/OpenSSL.h>
#include <openssl/evp.h>

namespace fizz {

struct ChaCha20Poly1305 {
#if FOLLY_OPENSSL_IS_110
  static constexpr auto Cipher = EVP_chacha20_poly1305;
#else
  static const EVP_CIPHER* Cipher() {
    throw std::runtime_error(
        "chacha20-poly1305 support requires OpenSSL 1.1.0");
  }
#endif // FOLLY_OPENSSL_IS_110

  static const size_t kKeyLength{32};
  static const size_t kIVLength{12};
  static const size_t kTagLength{16};
};

} // namespace fizz
