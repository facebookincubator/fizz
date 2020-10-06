/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>
#include <fizz/crypto/Hpke.h>
#include <fizz/crypto/Sha256.h>
#include <fizz/crypto/HpkeUtils.h>
#include <fizz/crypto/aead/test/TestUtil.h>
#include <fizz/crypto/test/TestUtil.h>
#include <fizz/crypto/test/HpkeMocks.h>

using namespace fizz::test;

namespace fizz {
namespace hpke {
namespace test {

struct Params {
  std::string key;
  std::string iv;
  CipherSuite cipher;
  std::string exporterSecret;
  std::string sharedSecret;
  std::string info;
  std::string psk;
  std::string pskId;
  Mode mode;
  NamedGroup group;
};

class HpkeTest : public ::testing::TestWithParam<Params> {};

MATCHER_P(TrafficKeyMatcher, expectedKey, "") {
	return folly::IOBufEqualTo()(expectedKey->iv, arg->iv) &&
    folly::IOBufEqualTo()(expectedKey->key, arg->key);
}

TEST_P(HpkeTest, TestKeySchedule) {
  const std::string kPrefix = "HPKE-05 ";
  std::unique_ptr<fizz::hpke::Hkdf> hkdf = std::make_unique<fizz::hpke::Hkdf>(
    folly::IOBuf::copyBuffer(kPrefix), std::make_unique<HkdfImpl>(HkdfImpl::create<Sha256>()));

  auto testParam = GetParam();

  std::unique_ptr<MockAeadCipher> cipher = std::make_unique<MockAeadCipher>(getCipher(testParam.cipher));
  std::unique_ptr<folly::IOBuf> suiteId = generateHpkeSuiteId(testParam.group, HashFunction::Sha256, testParam.cipher);
  TrafficKey expectedTrafficKey{toIOBuf(testParam.key), toIOBuf(testParam.iv)};
  EXPECT_CALL(*cipher, _setKey(TrafficKeyMatcher(&expectedTrafficKey))).Times(1);

  folly::Optional<PskInputs> pskInputs;
  if (testParam.psk.length() != 0 && testParam.pskId.length() != 0) {
    pskInputs = PskInputs(testParam.mode, toIOBuf(testParam.psk), toIOBuf(testParam.pskId));
  }

  struct KeyScheduleParams keyScheduleParams{testParam.mode, toIOBuf(testParam.sharedSecret), toIOBuf(testParam.info), std::move(pskInputs), std::move(cipher), std::move(hkdf), std::move(suiteId)};
  auto context = keySchedule(std::move(keyScheduleParams));

  EXPECT_TRUE(folly::IOBufEqualTo()(context.getExporterSecret(), toIOBuf(testParam.exporterSecret)));
}

/***
 * Test vectors sourced from Cisco's HPKE implementation (based on HPKE IETF draft).
 * https://raw.githubusercontent.com/cisco/go-hpke/9e7d3e90b7c3a5b08f3099c49520c587568c77d6/test-vectors.json
 */
// clang-format off

INSTANTIATE_TEST_CASE_P(
    TestVectors,
    HpkeTest,
    ::testing::
        Values(
            Params{
                "8d0dc124bbfe13e4ca468b13dcf4372f",
                "6da984dd38f0c4dcc2ea52c8",
                CipherSuite::TLS_AES_128_GCM_SHA256,
                "9aae234e8e43f4eba3b812f84f69b95c9c1959a27e57740e00dac8214513407b",
                "dc9e87081e93d16db6bac8ca600863d5cd6a1a40a91da147c644bdb35f965856",
                "4f6465206f6e2061204772656369616e2055726e",
                "5db3b80a81cb63ca59470c83414ef70a",
                "456e6e796e20447572696e206172616e204d6f726961",
                Mode::Psk,
                NamedGroup::secp256r1},
             Params{
                "f0529818bc7e87857fd38eeca1a47020",
                "4bbcb168c8486e04b9382642",
                CipherSuite::TLS_AES_128_GCM_SHA256,
                "4f6180a492f231ea225cc480330b83ce4adc2d772b14c71540ddb6a8e15ecbaf",
                "39803a02e487ed0031a44e32992f871ae3468675aaeb6d8a388acb0cf25058d3",
                "4f6465206f6e2061204772656369616e2055726e",
                "5db3b80a81cb63ca59470c83414ef70a",
                "456e6e796e20447572696e206172616e204d6f726961",
                Mode::Psk,
                NamedGroup::x25519},
            Params{
                "35954ba742888d312ad5c6c6f1f847a133070d6177dcadb6a35ea8a7169e80a3",
                "05e2b39adac37613ed2b3672",
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
                "777796a7a2937fe3f2d1ccb4f5412adf8b8df2cbcf9ad392fdac8db3e8e171fc",
                "a49abf4b375f089c7ac1cacc59f61f57917cc23ac32724d4c974f0485026baef",
                "4f6465206f6e2061204772656369616e2055726e",
                "",
                "",
                Mode::Auth,
                NamedGroup::x25519},
            Params{
                "d630907b86b891edc8f2c9bac1c3e4f7cd4e562576f34540f43ddd4b8bad3414",
                "5ba81ca3f83bdaedacfe80d6",
                CipherSuite::TLS_AES_256_GCM_SHA384,
                "0e5fe1dc378dd9fadc53d980e40b084366f8554bbffdeb1b26ca0c7c79808ca7",
                "6d2eb12e4abab5d6f98a6879ea8f8fef154aca88d0beb954446b712fbadb1208",
                "4f6465206f6e2061204772656369616e2055726e",
                "5db3b80a81cb63ca59470c83414ef70a",
                "456e6e796e20447572696e206172616e204d6f726961",
                Mode::AuthPsk,
                NamedGroup::secp256r1},
            Params{
                "bcce0b55c01db9e263216a07620ef48c",
                "c898fab947d4ce4ab97b015f",
                CipherSuite::TLS_AES_128_GCM_SHA256,
                "9fc90394e65c791d740537937295dbfaf2b1e6e0a1228bd8497b07c9cc1c4af8",
                "f9c5bfc0f8fbf63e9fe9af612aefc82416722a1e1cfa3b826df3b7f096f6dd486b81e18c9d08f8f0a76c53dc8a87364223ce39601b7ed849af2f3d18f751a887",
                "4f6465206f6e2061204772656369616e2055726e",
                "",
                "",
                Mode::Base,
                NamedGroup::secp521r1},
            Params{
                "69100ccf464b54fade60956ab2618038",
                "6e356f49030c57eff82b2426",
                CipherSuite::TLS_AES_128_GCM_SHA256,
                "b69d1ef605c37c8add2d0efbaee390a778ae4095d28d640cae76eb82d2370d7a",
                "b14167da17b5ad1af8660ac9a74772abb7943256c20214709ed304a0a23fb49c",
                "4f6465206f6e2061204772656369616e2055726e",
                "",
                "",
                Mode::Auth,
                NamedGroup::x25519}
    ));
// clang-format on

} // namespace test
} // namespace hpke
} // namespace fizz
