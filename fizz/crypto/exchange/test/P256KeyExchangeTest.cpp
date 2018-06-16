/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <fizz/crypto/exchange/P256KeyExchange.h>
#include <fizz/crypto/test/TestUtil.h>
#include <folly/String.h>
#include <folly/ssl/OpenSSLPtrTypes.h>

#include <openssl/ec.h>

using namespace folly;
using namespace folly::ssl;

namespace fizz {
namespace test {

using Kex = P256KeyExchange;

TEST(KeyExchange, GenerateKey) {
  Kex kex;
  kex.generateKeyPair();
}

TEST(KeyExchange, SharedSecret) {
  Kex kex;
  kex.generateKeyPair();
  auto shared = kex.generateSharedSecret(kex.getKey());
  EXPECT_TRUE(shared);
}

TEST(KeyExchange, ReadFromKey) {
  auto pkey = getPrivateKey(kP256Key);
  Kex kex;
  kex.setPrivateKey(std::move(pkey));

  auto pkey2 = getPrivateKey(kP256Key);
  Kex kex2;
  kex2.setPrivateKey(std::move(pkey2));
  auto shared = kex.generateSharedSecret(kex2.getKey());
  EXPECT_TRUE(shared);
}

TEST(KeyExchange, ReadWrongGroup) {
  auto pkey = getPrivateKey(kP256K1Key);
  Kex kex;
  EXPECT_THROW(kex.setPrivateKey(std::move(pkey)), std::runtime_error);
}

TEST(KeyExchange, Decode) {
  // Obtained from a key share from firefox nightly
  constexpr StringPiece encodedShare =
      "048d5e897c896b17e1679766c14c785dd2c328c3"
      "eecc7dbfd2e2e817cd35c786aceea79bf1286ab8"
      "a5c3c464c46f5ba06338b24ea96ce442a4d13356"
      "902dfcd1e9";
  std::string out = unhexlify(encodedShare);
  auto pub = P256PublicKeyDecoder::decode(range(out));
  EXPECT_TRUE(pub);
}

TEST(KeyExchange, Encode) {
  // Obtained from a key share from firefox nightly
  constexpr StringPiece encodedShare =
      "048d5e897c896b17e1679766c14c785dd2c328c3"
      "eecc7dbfd2e2e817cd35c786aceea79bf1286ab8"
      "a5c3c464c46f5ba06338b24ea96ce442a4d13356"
      "902dfcd1e9";
  std::string out = unhexlify(encodedShare);
  auto pub = P256PublicKeyDecoder::decode(range(out));
  EXPECT_TRUE(pub);
  auto encoded = P256PublicKeyEncoder::encode(pub);

  auto encodedStr = encoded->moveToFbString();
  EXPECT_EQ(encodedStr, out);
}

TEST(KeyExchange, DecodeInvalid) {
  // Obtained from a key share from firefox nightly, and modified slightly.
  constexpr StringPiece encodedShare =
      "048d5e897c896b17e1679766c14c785dd2c328c3"
      "eecc7dbfd2e2e817cd35c786abeea79bf1286ab8"
      "a5c3c464c46f5ba06338b24ea96ce442a4d13356"
      "902dfcd1e9";
  std::string out = unhexlify(encodedShare);
  EXPECT_THROW(P256PublicKeyDecoder::decode(range(out)), std::runtime_error);
}

TEST(KeyExchange, DecodeInvalidSmallLength) {
  // Obtained from a key share from firefox nightly, and modified slightly.
  constexpr StringPiece encodedShare =
      "048d5e897c896b17e1679766c14c785dd2c328c3";
  std::string out = unhexlify(encodedShare);
  EXPECT_THROW(P256PublicKeyDecoder::decode(range(out)), std::runtime_error);
}

struct Params {
  std::string peerPriv; // dsCAVS
  std::string peerX; // QsCAVSx
  std::string peerY; // QsCAVSy
  std::string priv; // dIUT
  std::string privX; // dIUTx
  std::string privY; // dIUTy
  std::string shared; // Z
  bool success;
};

class ECDHTest : public ::testing::TestWithParam<Params> {};

void setPoint(EcKeyUniquePtr& key, std::string x, std::string y) {
  auto binX = unhexlify(x);
  auto binY = unhexlify(y);
  BIGNUMUniquePtr numX(BN_bin2bn((uint8_t*)binX.data(), binX.size(), nullptr));
  BIGNUMUniquePtr numY(BN_bin2bn((uint8_t*)binY.data(), binY.size(), nullptr));
  EC_KEY_set_public_key_affine_coordinates(key.get(), numX.get(), numY.get());
}

EvpPkeyUniquePtr getKey(const Params& param) {
  auto privKeyBin = unhexlify(param.priv);
  BIGNUMUniquePtr privateBn(
      BN_bin2bn((uint8_t*)privKeyBin.c_str(), privKeyBin.size(), nullptr));
  EcKeyUniquePtr privateKey(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  EC_KEY_set_private_key(privateKey.get(), privateBn.get());
  setPoint(privateKey, param.privX, param.privY);
  EvpPkeyUniquePtr pkeyPrivateKey(EVP_PKEY_new());
  EVP_PKEY_set1_EC_KEY(pkeyPrivateKey.get(), privateKey.get());
  return pkeyPrivateKey;
}

TEST_P(ECDHTest, TestKeyAgreement) {
  try {
    auto privateKey = getKey(GetParam());
    ASSERT_TRUE(privateKey);
    // Create the peer key
    EcKeyUniquePtr peerKey(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    setPoint(peerKey, GetParam().peerX, GetParam().peerY);

    EvpPkeyUniquePtr pkeyPeerKey(EVP_PKEY_new());
    ASSERT_EQ(1, EVP_PKEY_set1_EC_KEY(pkeyPeerKey.get(), peerKey.get()));

    Kex kex;
    kex.setPrivateKey(std::move(privateKey));

    auto shared = kex.generateSharedSecret(pkeyPeerKey);
    ASSERT_TRUE(shared);
    auto sharedString = shared->moveToFbString();
    auto hexShared = hexlify(sharedString);
    if (GetParam().success) {
      EXPECT_EQ(GetParam().shared, hexShared);
    } else {
      EXPECT_NE(GetParam().shared, hexShared);
    }
  } catch (const std::runtime_error& ex) {
    EXPECT_FALSE(GetParam().success) << ex.what();
  }
}

/***
 * Test vectors sourced from
 * https://github.com/pyca/cryptography/blob/1a6628e55126ec1c98c98a46c04f777f77eff934/vectors/cryptography_vectors/asymmetric/ECDH/KASValidityTest_ECCStaticUnified_NOKC_ZZOnly_init.fax
 * These are NIST test vectors.
 */
INSTANTIATE_TEST_CASE_P(
    TestVectors,
    ECDHTest,
    ::testing::Values(
        (Params){
            "e19007eb245d6995ffa8b3ede1e59193aa6cfaaf4cc1e1d126948610c9b3f44c",
            "758b2f0e79a3d0a94f521ae31dcff50fabd394bb4bbec8fa37d1566f463444e7",
            "b981e686e53e9e9dc2e3f263e810c89b4c271e62392f59ed45ed30ac3a5bfd33",
            "8171000763de347d0eb650dd6fddac2ad48ec122c162d66c3df257aea13192fb",
            "c22ac2ee50e771a93b2b6a42c5e9b76b45a56e0d0011e34aa790283ede61f3d9",
            "0ef754edae5e79c518f1056aa5179cbb6a3a4b7c9654b5048f4259bd2597e57d",
            "5cbea453310285b22f128178bd09b906fde9e660b5a17a7cec809a5a9a1e9287",
            true},
        (Params){
            "0ced658b6113979f8d05fd7b305ce0b8d70f45034d021b052cbcb318e0cfd602",
            "acbcb31f5f6798a00f28aa4a634873744768db612925336efca98122a76d1b5e",
            "7dcefeb3ccb530029a8b62e5a7f00c42fc7ebeac8f469c289ea77b6186d661f0",
            "64e23f7a2d279930f1de66b4bc147786b168d059f581268c24f6650362246e63",
            "ba393b401354aa9552c4289b7a55288d97590429a4003913a243081bacf88acf",
            "d089687aa5442684d71b805ea2b36f6c1c783833346dfdd8208768ed2a7e767d",
            "f70e4fc9ba68aafe07be1767620e64dd5e5bb7ab279f0657465cddeb69e36fa9",
            true},
        (Params){
            "0ced658b6113979f8d05fd7b305ce0b8d70f45034d021b052cbcb318e0cfd602",
            "758b2f0e79a3d0a94f521ae31dcff50fabd394bb4bbec8fa37d1566f463444e7",
            "b981e686e53e9e9dc2e3f263e810c89b4c271e62392f59ed45ed30ac3a5bfd33",
            "8171000763de347d0eb650dd6fddac2ad48ec122c162d66c3df257aea13192fb",
            "c22ac2ee50e771a93b2b6a42c5e9b76b45a56e0d0011e34aa790283ede61f3d9",
            "0ef754edae5e79c518f1056aa5179cbb6a3a4b7c9654b5048f4259bd2597e57d",
            "5cbea453310285b22f128178bd09b906fde9e660b5a17a7cec809a5a9a1e9287",
            true},
        (Params){
            "639ef9ee75a3888617fdd7ed89d62f7398b0eb4f20ccbd35026e150fc937c927",
            "1d2dda4a3735be1f3aedfa8a7bb1410c3867c5d67f55a3dd5376b137352f113d",
            "eca92fb210b1813f51ea2483ff461eb24786afb41f1a00870cf65aab5bbd725e",
            "e062138981049c3b4b964fa5a28569e0142c2c51d6ca0bebdb3270e2ab77fb30",
            "9aa8dd75f7d929b1f5f123aa9f3265be34f771c20bb50deea684a139a10938f8",
            "2b74f503fa7b08db1c76d97c2e571cb91f68a93413daf102c47fee1b8a264d93",
            "9f5f64d76f9bb2f2af24debdd47323d5df9d2b84fc7c7aac1f6d41678adec7de",
            false},
        (Params){
            "305dfb4a8850cc59280891147baf457bfe5e2bae984571634a77dc8d3472fa9b",
            "202cb5a224e6c2a84e624094486edf04116c8d68ec1f4a0e0ed9ee090e1a900b",
            "cacf3a5789bb33954be600425d62d9eae5371f90f88167258814213e4a4f4b1a",
            "72cc52808f294b64b6f7233c3d2f5d96cc1d29287320e39e1c151deef0bc14eb",
            "49a768c9a4ca56e374f685dd76a461b1016c59dcded2c8d8cbd9f23ca453831f",
            "b1e3bb9b5f12a3b5ae788535d4554bd8c46e0e6130075e4e437d3854cf8f1c34",
            "c0147c3c2691b450b5edc08b51aea224d9f4359ff67aab6da3146f396dbceaea",
            false}));
} // namespace test
} // namespace fizz
