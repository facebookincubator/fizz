/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>

#include <fizz/backend/openssl/crypto/exchange/X25519.h>
#include <fizz/fizz-config.h>
#include <fizz/util/Status.h>
#include <folly/Range.h>
#include <folly/String.h>

#include <array>
#include <tuple>

#if FIZZ_HAVE_SODIUM
#include <fizz/backend/libsodium/crypto/exchange/X25519.h>
#endif

using namespace folly;

namespace fizz {
namespace test {

namespace {
std::unique_ptr<folly::IOBuf> fromHex(StringPiece hex) {
  return folly::IOBuf::copyBuffer(folly::unhexlify(hex));
}

// RFC 7748, section 6.1.
constexpr StringPiece kAlicePrivateKey =
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
constexpr StringPiece kAlicePublicKey =
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
constexpr StringPiece kBobPrivateKey =
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
constexpr StringPiece kBobPublicKey =
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
constexpr StringPiece kSharedSecret =
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
} // namespace

template <typename T>
class X25519KeyExchangeTest : public ::testing::Test {};

using X25519Implementations = ::testing::Types<
#if FIZZ_HAVE_SODIUM
    libsodium::X25519KeyExchange,
#endif
    openssl::X25519KeyExchange>;
TYPED_TEST_SUITE(X25519KeyExchangeTest, X25519Implementations);

TYPED_TEST(X25519KeyExchangeTest, KeyExchange) {
  static constexpr StringPiece keyShareHex =
      "c81e57c7485ba417280bc2d48d864afd3966ff77b684bfaf85f418f9b4583347";
  auto keyShare = unhexlify(keyShareHex);
  TypeParam kex;
  Error err;
  EXPECT_EQ(kex.generateKeyPair(err), Status::Success);
  std::unique_ptr<folly::IOBuf> out;
  EXPECT_EQ(
      kex.generateSharedSecret(out, err, folly::range(keyShare)),
      Status::Success);
}

TYPED_TEST(X25519KeyExchangeTest, SmallKeyExchange) {
  static constexpr StringPiece keyShareHex = "c81e57c7485ba4";
  auto keyShare = unhexlify(keyShareHex);
  TypeParam kex;
  Error err;
  EXPECT_EQ(kex.generateKeyPair(err), Status::Success);
  EXPECT_THROW(
      {
        std::unique_ptr<folly::IOBuf> out;
        FIZZ_THROW_ON_ERROR(
            kex.generateSharedSecret(out, err, folly::range(keyShare)), err);
      },
      std::runtime_error);
}

TYPED_TEST(X25519KeyExchangeTest, KeyExchangeClone) {
  static constexpr StringPiece keyShareHex =
      "c81e57c7485ba417280bc2d48d864afd3966ff77b684bfaf85f418f9b4583347";
  auto keyShare = unhexlify(keyShareHex);
  TypeParam kex;
  Error err;
  EXPECT_EQ(kex.generateKeyPair(err), Status::Success);

  std::unique_ptr<folly::IOBuf> sharedSecret;
  EXPECT_EQ(
      kex.generateSharedSecret(sharedSecret, err, folly::range(keyShare)),
      Status::Success);

  // Copy current key exchange
  std::unique_ptr<KeyExchange> kexCopy;
  EXPECT_EQ(kex.clone(kexCopy, err), Status::Success);
  std::unique_ptr<folly::IOBuf> sharedSecretOfCopy;
  EXPECT_EQ(
      kexCopy->generateSharedSecret(
          sharedSecretOfCopy, err, folly::range(keyShare)),
      Status::Success);

  EXPECT_TRUE(folly::IOBufEqualTo()(sharedSecret, sharedSecretOfCopy));
}

TYPED_TEST(X25519KeyExchangeTest, setPrivateKeyTest) {
  TypeParam kex;
  Error err;
  EXPECT_EQ(
      kex.setPrivateKey(
          err,
          fromHex(
              "4d649ccc95beabba04637a4c14bcca98069511754a38807460a675f784dc3d75")),
      Status::Success);

  std::unique_ptr<folly::IOBuf> gotKeyShare;
  EXPECT_EQ(kex.getKeyShare(gotKeyShare, err), Status::Success);

  auto expectedKeyShare = fromHex(
      "2c908774a108700951a233e9efad4788f5fd42247e0978b84e96e0a6eb33716c");

  EXPECT_TRUE(folly::IOBufEqualTo()(expectedKeyShare, gotKeyShare));
}

TYPED_TEST(X25519KeyExchangeTest, KnownAnswer) {
  for (auto [privateKey, publicKey, peerPublicKey] :
       {std::tuple{kAlicePrivateKey, kAlicePublicKey, kBobPublicKey},
        std::tuple{kBobPrivateKey, kBobPublicKey, kAlicePublicKey}}) {
    TypeParam kex;
    Error err;
    ASSERT_EQ(kex.setPrivateKey(err, fromHex(privateKey)), Status::Success);

    std::unique_ptr<folly::IOBuf> keyShare;
    ASSERT_EQ(kex.getKeyShare(keyShare, err), Status::Success);
    EXPECT_TRUE(folly::IOBufEqualTo()(keyShare, fromHex(publicKey)));

    auto peerKeyShare = unhexlify(peerPublicKey);
    std::unique_ptr<folly::IOBuf> sharedSecret;
    ASSERT_EQ(
        kex.generateSharedSecret(sharedSecret, err, folly::range(peerKeyShare)),
        Status::Success);
    EXPECT_TRUE(folly::IOBufEqualTo()(sharedSecret, fromHex(kSharedSecret)));
  }
}

TYPED_TEST(X25519KeyExchangeTest, SmallOrderPoint) {
  TypeParam kex;
  Error err;
  ASSERT_EQ(kex.setPrivateKey(err, fromHex(kAlicePrivateKey)), Status::Success);
  // The shared secret with a point of small order is all zeros, which is
  // rejected.
  for (uint8_t firstByte : {0, 1}) {
    std::array<uint8_t, 32> point{};
    point[0] = firstByte;
    std::unique_ptr<folly::IOBuf> sharedSecret;
    EXPECT_EQ(
        kex.generateSharedSecret(sharedSecret, err, folly::range(point)),
        Status::Fail);
  }
}

TYPED_TEST(X25519KeyExchangeTest, InvalidPrivateKey) {
  TypeParam kex;
  Error err;
  EXPECT_EQ(kex.setPrivateKey(err, nullptr), Status::Fail);
  EXPECT_EQ(
      kex.setPrivateKey(err, folly::IOBuf::copyBuffer(std::string(31, 'a'))),
      Status::Fail);
}

TYPED_TEST(X25519KeyExchangeTest, NotGenerated) {
  TypeParam kex;
  Error err;
  std::unique_ptr<folly::IOBuf> keyShare;
  EXPECT_EQ(kex.getKeyShare(keyShare, err), Status::Fail);
  std::unique_ptr<KeyExchange> kexCopy;
  EXPECT_EQ(kex.clone(kexCopy, err), Status::Fail);
}

#if FIZZ_HAVE_SODIUM
TEST(X25519KeyExchangeInterop, LibsodiumAndOpenSSL) {
  libsodium::X25519KeyExchange sodiumKex;
  openssl::X25519KeyExchange opensslKex;
  Error err;
  ASSERT_EQ(sodiumKex.generateKeyPair(err), Status::Success);
  ASSERT_EQ(opensslKex.generateKeyPair(err), Status::Success);

  std::unique_ptr<folly::IOBuf> sodiumKeyShare;
  std::unique_ptr<folly::IOBuf> opensslKeyShare;
  ASSERT_EQ(sodiumKex.getKeyShare(sodiumKeyShare, err), Status::Success);
  ASSERT_EQ(opensslKex.getKeyShare(opensslKeyShare, err), Status::Success);

  std::unique_ptr<folly::IOBuf> sodiumSecret;
  std::unique_ptr<folly::IOBuf> opensslSecret;
  ASSERT_EQ(
      sodiumKex.generateSharedSecret(
          sodiumSecret, err, opensslKeyShare->coalesce()),
      Status::Success);
  ASSERT_EQ(
      opensslKex.generateSharedSecret(
          opensslSecret, err, sodiumKeyShare->coalesce()),
      Status::Success);
  EXPECT_TRUE(folly::IOBufEqualTo()(sodiumSecret, opensslSecret));
}
#endif

} // namespace test
} // namespace fizz
