/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/Hkdf.h>
#include <fizz/crypto/aead/OpenSSLEVPCipher.h>
#include <fizz/protocol/Types.h>
#include <fizz/server/AeadTicketCipher.h>
#include <fizz/server/TicketCodec.h>

namespace fizz {
namespace server {
using AES128TicketCipher = AeadTicketCipher<
    OpenSSLEVPCipher<AESGCM128>,
    TicketCodec<CertificateStorage::X509>,
    HkdfImpl<Sha256>>;
using AES128TicketIdentityOnlyCipher = AeadTicketCipher<
    OpenSSLEVPCipher<AESGCM128>,
    TicketCodec<CertificateStorage::IdentityOnly>,
    HkdfImpl<Sha256>>;
using AES128TokenCipher =
    AeadTokenCipher<OpenSSLEVPCipher<AESGCM128>, HkdfImpl<Sha256>>;
} // namespace server
} // namespace fizz
