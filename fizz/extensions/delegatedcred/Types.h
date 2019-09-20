/*
 *  Copyright (c) 2019-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */
#pragma once

#include <fizz/record/Extensions.h>
#include <fizz/record/Types.h>
#include <folly/Optional.h>

namespace fizz {
namespace extensions {

struct DelegatedCredential {
  uint32_t valid_time;
  SignatureScheme expected_verify_scheme;
  Buf public_key;
  SignatureScheme credential_scheme;
  Buf signature;
};

struct DelegatedCredentialSupport {};

} // namespace extensions

template <>
folly::Optional<extensions::DelegatedCredential> getExtension(
    const std::vector<Extension>& extensions);

template <>
Extension encodeExtension(const extensions::DelegatedCredential& cred);

} // namespace fizz
