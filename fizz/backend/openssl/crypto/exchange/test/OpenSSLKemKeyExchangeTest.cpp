/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>

#include <fizz/backend/openssl/crypto/exchange/OpenSSLKemKeyExchange.h>
#include <fizz/protocol/MultiBackendFactory.h>
#include <fizz/record/Types.h>
#include <fizz/util/Status.h>

#include <folly/Range.h>
#include <openssl/opensslv.h>

#include <array>

#if OPENSSL_VERSION_NUMBER >= 0x30500000L

namespace fizz {
namespace openssl {
namespace test {

constexpr char kGroup[] = "X25519MLKEM768";

bool kemAvailable() {
  return isKemGroupAvailable(kGroup);
}

// KEM round-trip: client keygen -> pub -> server encapsulate -> cipher ->
// client decapsulate, and both sides derive an identical shared secret.
TEST(OpenSSLKemKeyExchange, RoundTrip) {
  if (!kemAvailable()) {
    GTEST_SKIP() << "X25519MLKEM768 not available in OpenSSL providers";
  }
  Error err;
  std::unique_ptr<KeyExchange> client;
  std::unique_ptr<KeyExchange> server;
  ASSERT_EQ(
      OpenSSLKemKeyExchange::createKeyExchange(
          client, err, KeyExchangeRole::Client, kGroup),
      Status::Success);
  ASSERT_EQ(
      OpenSSLKemKeyExchange::createKeyExchange(
          server, err, KeyExchangeRole::Server, kGroup),
      Status::Success);

  ASSERT_EQ(client->generateKeyPair(err), Status::Success);
  std::unique_ptr<folly::IOBuf> clientShare;
  ASSERT_EQ(client->getKeyShare(clientShare, err), Status::Success);
  ASSERT_TRUE(clientShare);

  std::unique_ptr<folly::IOBuf> serverSecret;
  ASSERT_EQ(
      server->generateSharedSecret(serverSecret, err, clientShare->coalesce()),
      Status::Success);
  std::unique_ptr<folly::IOBuf> serverShare;
  ASSERT_EQ(server->getKeyShare(serverShare, err), Status::Success);

  std::unique_ptr<folly::IOBuf> clientSecret;
  ASSERT_EQ(
      client->generateSharedSecret(clientSecret, err, serverShare->coalesce()),
      Status::Success);

  EXPECT_TRUE(folly::IOBufEqualTo()(serverSecret, clientSecret));
  EXPECT_GT(clientSecret->computeChainDataLength(), 0u);
}

// clone() must share the keypair (up_ref) and yield the same shared secret.
TEST(OpenSSLKemKeyExchange, CloneClient) {
  if (!kemAvailable()) {
    GTEST_SKIP() << "X25519MLKEM768 not available";
  }
  Error err;
  std::unique_ptr<KeyExchange> client;
  ASSERT_EQ(
      OpenSSLKemKeyExchange::createKeyExchange(
          client, err, KeyExchangeRole::Client, kGroup),
      Status::Success);
  ASSERT_EQ(client->generateKeyPair(err), Status::Success);

  std::unique_ptr<KeyExchange> clone;
  ASSERT_EQ(client->clone(clone, err), Status::Success);

  std::unique_ptr<folly::IOBuf> a;
  std::unique_ptr<folly::IOBuf> b;
  ASSERT_EQ(client->getKeyShare(a, err), Status::Success);
  ASSERT_EQ(clone->getKeyShare(b, err), Status::Success);
  EXPECT_TRUE(folly::IOBufEqualTo()(a, b));
}

TEST(OpenSSLKemKeyExchange, ExpectedSizes) {
  if (!kemAvailable()) {
    GTEST_SKIP() << "X25519MLKEM768 not available";
  }
  Error err;
  std::unique_ptr<KeyExchange> client;
  std::unique_ptr<KeyExchange> server;
  ASSERT_EQ(
      OpenSSLKemKeyExchange::createKeyExchange(
          client, err, KeyExchangeRole::Client, kGroup),
      Status::Success);
  ASSERT_EQ(
      OpenSSLKemKeyExchange::createKeyExchange(
          server, err, KeyExchangeRole::Server, kGroup),
      Status::Success);
  // Server expects the client public key; client expects the ciphertext.
  EXPECT_GT(server->getExpectedKeyShareSize(), 0u);
  EXPECT_GT(client->getExpectedKeyShareSize(), 0u);
}

// Decapsulating a malformed (too short) ciphertext must fail cleanly.
TEST(OpenSSLKemKeyExchange, BadCiphertextFails) {
  if (!kemAvailable()) {
    GTEST_SKIP() << "X25519MLKEM768 not available";
  }
  Error err;
  std::unique_ptr<KeyExchange> client;
  ASSERT_EQ(
      OpenSSLKemKeyExchange::createKeyExchange(
          client, err, KeyExchangeRole::Client, kGroup),
      Status::Success);
  ASSERT_EQ(client->generateKeyPair(err), Status::Success);
  std::array<uint8_t, 8> bogus{};
  std::unique_ptr<folly::IOBuf> secret;
  EXPECT_EQ(
      client->generateSharedSecret(secret, err, folly::range(bogus)),
      Status::Fail);
}

// Encapsulating to a malformed (too short) peer public key must fail cleanly.
TEST(OpenSSLKemKeyExchange, BadPeerKeyFails) {
  if (!kemAvailable()) {
    GTEST_SKIP() << "X25519MLKEM768 not available";
  }
  Error err;
  std::unique_ptr<KeyExchange> server;
  ASSERT_EQ(
      OpenSSLKemKeyExchange::createKeyExchange(
          server, err, KeyExchangeRole::Server, kGroup),
      Status::Success);
  std::array<uint8_t, 8> bogus{};
  std::unique_ptr<folly::IOBuf> secret;
  EXPECT_EQ(
      server->generateSharedSecret(secret, err, folly::range(bogus)),
      Status::Fail);
}

// Negotiation: when the native provider is available, MultiBackendFactory must
// hand back the native KEM; otherwise it falls back to liboqs (if built).
TEST(OpenSSLKemKeyExchange, FactoryPrefersNative) {
  Error err;
  MultiBackendFactory factory;
  std::unique_ptr<KeyExchange> kex;
  auto st = factory.makeKeyExchange(
      kex, err, NamedGroup::X25519MLKEM768, KeyExchangeRole::Client);
#if FIZZ_HAVE_OQS
  EXPECT_EQ(st, Status::Success);
  EXPECT_TRUE(kex);
#else
  if (kemAvailable()) {
    EXPECT_EQ(st, Status::Success);
    EXPECT_TRUE(kex);
  }
#endif
}
} // namespace test
} // namespace openssl
} // namespace fizz

#endif // OPENSSL_VERSION_NUMBER >= 0x30500000L
