/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <fizz/crypto/signature/Signature.h>
#include <folly/String.h>

using namespace folly;
using namespace folly::ssl;

namespace fizz {
namespace testing {

struct Params {
  std::string msg;
  std::string priv; // x
  std::string pubX; // Ux
  std::string pubY; // Uy
};

class ECDSATest : public ::testing::TestWithParam<Params> {
  void SetUp() override {
    OpenSSL_add_all_algorithms();
  }
};

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
  setPoint(privateKey, param.pubX, param.pubY);
  EvpPkeyUniquePtr pkeyPrivateKey(EVP_PKEY_new());
  EVP_PKEY_set1_EC_KEY(pkeyPrivateKey.get(), privateKey.get());
  return pkeyPrivateKey;
}

TEST_P(ECDSATest, TestSignaturePasses) {
  auto key = getKey(GetParam());
  OpenSSLSignature<KeyType::P256> ecdsa;
  ecdsa.setKey(std::move(key));
  std::string msg = GetParam().msg;
  auto sig = ecdsa.sign<SignatureScheme::ecdsa_secp256r1_sha256>(
      IOBuf::copyBuffer(msg)->coalesce());
  ecdsa.verify<SignatureScheme::ecdsa_secp256r1_sha256>(
      IOBuf::copyBuffer(msg)->coalesce(), sig->coalesce());
}

TEST_P(ECDSATest, TestSigModified) {
  auto key = getKey(GetParam());
  OpenSSLSignature<KeyType::P256> ecdsa;
  ecdsa.setKey(std::move(key));
  std::string msg = GetParam().msg;
  auto sig = ecdsa.sign<SignatureScheme::ecdsa_secp256r1_sha256>(
      IOBuf::copyBuffer(msg)->coalesce());
  auto& sigPtr = sig->writableData()[10];
  if (sigPtr == 1) {
    sigPtr = 2;
  } else {
    sigPtr = 1;
  }
  EXPECT_THROW(
      ecdsa.verify<SignatureScheme::ecdsa_secp256r1_sha256>(
          IOBuf::copyBuffer(msg)->coalesce(), sig->coalesce()),
      std::runtime_error);
}

TEST_P(ECDSATest, TestDataModified) {
  auto key = getKey(GetParam());
  OpenSSLSignature<KeyType::P256> ecdsa;
  ecdsa.setKey(std::move(key));
  std::string msg = GetParam().msg;
  auto sig = ecdsa.sign<SignatureScheme::ecdsa_secp256r1_sha256>(
      IOBuf::copyBuffer(msg)->coalesce());
  auto& sigPtr = sig->writableData()[10];
  if (sigPtr == 1) {
    sigPtr = 2;
  } else {
    sigPtr = 1;
  }
  auto& msgPtr = msg[2];
  if (msgPtr == 1) {
    msgPtr = 2;
  } else {
    msgPtr = 1;
  }
  EXPECT_THROW(
      ecdsa.verify<SignatureScheme::ecdsa_secp256r1_sha256>(
          IOBuf::copyBuffer(msg)->coalesce(), sig->coalesce()),
      std::runtime_error);
}

// Test vector from https://tools.ietf.org/html/rfc6979#appendix-A.2.5
// We can't test those directly since we'd need to use the more complicated
// API of actually setting k and dealing with ECDSA_sig objects directly.
INSTANTIATE_TEST_CASE_P(
    TestVectors,
    ECDSATest,
    ::testing::Values((Params){
        "sample",
        "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
        "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"}));
} // namespace testing
} // namespace fizz
