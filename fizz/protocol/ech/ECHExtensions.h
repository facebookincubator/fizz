/*
 *  Copyright (c) 2019-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <vector>
#include <cstdint>

#include <fizz/protocol/ech/Types.h>
#include <fizz/record/Types.h>

namespace fizz {
namespace ech {
struct EncryptedClientHello {
  // The ECHCipherSuite cipher suite used to encrypt
  // ClientHelloInner.
  ECHCipherSuite suite;
  // A cryptographic hash of the ECHConfig structure from
  // which the ECH key was obtained.
  Buf record_digest;
  // The HPKE encapsulated key, used by servers to
  // decrypt the corresponding encrypted_ch field.
  Buf enc;
  // The serialized and encrypted ClientHelloInner
  // structure, AEAD-encrypted using HPKE with the selected KEM, KDF,
  // and AEAD algorithm and key generated as described below.
  Buf encrypted_ch;

  static constexpr ExtensionType extension_type =
    ExtensionType::encrypted_client_hello;
};

struct ECHNonce {
  // A 16-byte nonce exported from the HPKE encryption context.
  HpkeNonce nonce;

  static constexpr ExtensionType extension_type =
    ExtensionType::ech_nonce;
};
} // namespace ech
} // namespace fizz

#include <fizz/protocol/ech/ECHExtensions-inl.h>
