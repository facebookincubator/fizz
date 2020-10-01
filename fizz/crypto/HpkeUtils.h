/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/HpkeTypes.h>
#include <fizz/protocol/Types.h>

namespace fizz {
namespace hpke {

HpkeSuiteId generateHpkeSuiteId(NamedGroup group, HashFunction hash, CipherSuite suite);
KEMId getKEMId(NamedGroup group);
KDFId getKDFId(HashFunction hash);
AeadId getAeadId(CipherSuite suite);

} // namespace hpke
} // namespace fizz
