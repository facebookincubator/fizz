/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/hpke/Types.h>

#include <fizz/crypto/aead/Aead.h>
#include <fizz/crypto/exchange/KeyExchange.h>
#include <fizz/crypto/hpke/Hkdf.h>
#include <fizz/protocol/Types.h>

namespace fizz {
namespace hpke {

HpkeSuiteId
generateHpkeSuiteId(NamedGroup group, HashFunction hash, CipherSuite suite);
KEMId getKEMId(NamedGroup group);
KDFId getKDFId(HashFunction hash);
AeadId getAeadId(CipherSuite suite);

NamedGroup getKexGroup(KEMId kemId);
HashFunction getHashFunction(KDFId kdfId);
CipherSuite getCipherSuite(AeadId aeadId);

std::unique_ptr<Hkdf> makeHpkeHkdf(
    std::unique_ptr<folly::IOBuf> prefix,
    KDFId kdfId);
std::unique_ptr<KeyExchange> makeKeyExchange(KEMId kemId);
std::unique_ptr<Aead> makeCipher(AeadId aeadId);

} // namespace hpke
} // namespace fizz
