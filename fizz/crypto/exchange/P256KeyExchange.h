/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/P256.h>
#include <fizz/crypto/exchange/OpenSSLKeyExchange.h>
#include <folly/io/IOBuf.h>

namespace fizz {

using P256KeyExchange = detail::OpenSSLECKeyExchange<P256>;
using P256PublicKeyDecoder = detail::OpenSSLECKeyDecoder<P256>;
using P256PublicKeyEncoder = detail::OpenSSLECKeyEncoder;
} // namespace fizz
