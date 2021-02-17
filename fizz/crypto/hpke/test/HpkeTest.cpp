/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/crypto/Sha256.h>
#include <fizz/crypto/hpke/Hpke.h>
#include <fizz/crypto/hpke/Utils.h>
#include <fizz/crypto/hpke/test/Mocks.h>
#include <fizz/crypto/test/TestUtil.h>
#include <gtest/gtest.h>

using namespace fizz::test;

namespace fizz {
namespace hpke {
namespace test {

struct Params {
  Mode mode;
  NamedGroup group;
  HashFunction hash;
  CipherSuite suite;
  std::string sharedSecret;
  std::string info;
  // Key pair used for encryption
  std::string skE;
  std::string pkE;
  // Key pair used for decryption
  std::string skR;
  std::string pkR;
  // Optional
  std::string psk;
  std::string pskId;
  // Expected traffic key
  std::string key;
  std::string iv;
  // Encryption/decryption
  std::string ciphertext;
  // Test exports
  std::string exporterSecret;
  std::array<std::string, 5> exportValues;
};

void testExportValues(
    HpkeContext context,
    const std::array<std::string, 5>& exportValues) {
  const size_t exportLength = 32;
  std::array<std::string, 5> testExportContexts = {
      "436f6e746578742d30",
      "436f6e746578742d31",
      "436f6e746578742d32",
      "436f6e746578742d33",
      "436f6e746578742d34"};

  for (int testNum = 0; testNum < 5; ++testNum) {
    std::unique_ptr<folly::IOBuf> exporterContext =
        toIOBuf(testExportContexts.at(testNum));
    auto secret =
        context.exportSecret(std::move(exporterContext), exportLength);
    auto expectedSecret = toIOBuf(exportValues.at(testNum));

    EXPECT_TRUE(folly::IOBufEqualTo()(secret, expectedSecret));
  }
}

MATCHER_P(TrafficKeyMatcher, expectedKey, "") {
  return folly::IOBufEqualTo()(expectedKey->iv, arg->iv) &&
      folly::IOBufEqualTo()(expectedKey->key, arg->key);
}

class HpkeMockX25519KeyExchange : public X25519KeyExchange {
 public:
  MOCK_METHOD0(generateKeyPair, void());
};

SetupParam getSetupParam(
    std::unique_ptr<X25519KeyExchange> kex,
    CipherSuite suite,
    std::string privateKey,
    std::string publicKey,
    std::unique_ptr<MockAeadCipher> cipher) {
  auto group = NamedGroup::x25519;
  kex->setKeyPair(toIOBuf(privateKey), toIOBuf(publicKey));

  std::unique_ptr<folly::IOBuf> suiteId =
      generateHpkeSuiteId(group, HashFunction::Sha256, suite);

  return SetupParam{
      std::make_unique<DHKEM>(
          std::move(kex),
          group,
          std::make_unique<fizz::hpke::Hkdf>(
              folly::IOBuf::copyBuffer("HPKE-05 "),
              std::make_unique<HkdfImpl>(HkdfImpl::create<Sha256>()))),
      std::move(cipher),
      std::make_unique<fizz::hpke::Hkdf>(
          folly::IOBuf::copyBuffer("HPKE-05 "),
          std::make_unique<HkdfImpl>(HkdfImpl::create<Sha256>())),
      std::move(suiteId),
  };
}

class HpkeTest : public ::testing::TestWithParam<Params> {};

TEST_P(HpkeTest, TestSetup) {
  auto testParam = GetParam();
  auto pkR = toIOBuf(testParam.pkR);
  auto info = toIOBuf(testParam.info);

  auto encapCipher =
      std::make_unique<MockAeadCipher>(getCipher(testParam.suite));
  TrafficKey encapExpectedTrafficKey{
      toIOBuf(testParam.key), toIOBuf(testParam.iv)};
  EXPECT_CALL(
      *encapCipher, _setKey(TrafficKeyMatcher(&encapExpectedTrafficKey)))
      .Times(1);
  auto encapKex = std::make_unique<HpkeMockX25519KeyExchange>();
  EXPECT_CALL(*encapKex, generateKeyPair()).Times(1);

  SetupResult setupResult = setupWithEncap(
      testParam.mode,
      pkR->coalesce(),
      info->clone(),
      PskInputs(
          testParam.mode, toIOBuf(testParam.psk), toIOBuf(testParam.pskId)),
      getSetupParam(
          std::move(encapKex),
          testParam.suite,
          testParam.skE,
          testParam.pkE,
          std::move(encapCipher)));
  HpkeContext encryptContext = std::move(setupResult.context);

  auto enc = std::move(setupResult.enc);
  auto decapCipher =
      std::make_unique<MockAeadCipher>(getCipher(testParam.suite));
  TrafficKey decapExpectedTrafficKey{
      toIOBuf(testParam.key), toIOBuf(testParam.iv)};
  EXPECT_CALL(
      *decapCipher, _setKey(TrafficKeyMatcher(&decapExpectedTrafficKey)))
      .Times(1);

  HpkeContext decryptContext = setupWithDecap(
      testParam.mode,
      enc->coalesce(),
      std::move(info),
      PskInputs(
          testParam.mode, toIOBuf(testParam.psk), toIOBuf(testParam.pskId)),
      getSetupParam(
          std::make_unique<X25519KeyExchange>(),
          testParam.suite,
          testParam.skR,
          testParam.pkR,
          std::move(decapCipher)));

  // Test encrypt/decrypt
  std::unique_ptr<folly::IOBuf> aad = toIOBuf("436f756e742d30");
  std::unique_ptr<folly::IOBuf> plaintext =
      toIOBuf("4265617574792069732074727574682c20747275746820626561757479");

  auto ciphertext = encryptContext.seal(aad.get(), plaintext->clone());
  auto expectedCiphertext = testParam.ciphertext;
  EXPECT_TRUE(folly::IOBufEqualTo()(ciphertext, toIOBuf(expectedCiphertext)));

  auto gotPlaintext = decryptContext.open(aad.get(), std::move(ciphertext));
  EXPECT_TRUE(folly::IOBufEqualTo()(gotPlaintext, plaintext));

  // Test exporter secret
  auto gotExporterSecretE = encryptContext.getExporterSecret();
  auto gotExporterSecretD = decryptContext.getExporterSecret();
  auto expectedExporterSecret = toIOBuf(testParam.exporterSecret);
  EXPECT_TRUE(
      folly::IOBufEqualTo()(gotExporterSecretE, expectedExporterSecret));
  EXPECT_TRUE(
      folly::IOBufEqualTo()(gotExporterSecretD, expectedExporterSecret));

  // Test export values
  testExportValues(std::move(encryptContext), testParam.exportValues);
  testExportValues(std::move(decryptContext), testParam.exportValues);
}

TEST_P(HpkeTest, TestKeySchedule) {
  const std::string kPrefix = "HPKE-05 ";
  std::unique_ptr<fizz::hpke::Hkdf> hkdf = std::make_unique<fizz::hpke::Hkdf>(
      folly::IOBuf::copyBuffer(kPrefix),
      std::make_unique<HkdfImpl>(HkdfImpl::create<Sha256>()));

  auto testParam = GetParam();

  std::unique_ptr<MockAeadCipher> cipher =
      std::make_unique<MockAeadCipher>(getCipher(testParam.suite));
  std::unique_ptr<folly::IOBuf> suiteId = generateHpkeSuiteId(
      testParam.group, HashFunction::Sha256, testParam.suite);
  TrafficKey expectedTrafficKey{toIOBuf(testParam.key), toIOBuf(testParam.iv)};
  EXPECT_CALL(*cipher, _setKey(TrafficKeyMatcher(&expectedTrafficKey)))
      .Times(1);

  struct KeyScheduleParams keyScheduleParams {
    testParam.mode, toIOBuf(testParam.sharedSecret), toIOBuf(testParam.info),
        PskInputs(
            testParam.mode,
            toIOBuf(testParam.psk),
            toIOBuf(testParam.pskId)),
        std::move(cipher), std::move(hkdf), std::move(suiteId)
  };
  auto context = keySchedule(std::move(keyScheduleParams));

  EXPECT_TRUE(folly::IOBufEqualTo()(
      context.getExporterSecret(), toIOBuf(testParam.exporterSecret)));
}

/***
 * Test vectors sourced from IETF's HPKE draft.
 * https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/580119bb7bb45fd09a1079b920f8ef257f901309/test-vectors.json
 */
// clang-format off

INSTANTIATE_TEST_CASE_P(
    TestVectors,
    HpkeTest,
    ::testing::
        Values(
            Params{
                Mode::Base,
                NamedGroup::x25519,
                HashFunction::Sha256,
                CipherSuite::TLS_AES_128_GCM_SHA256,
                "f3822302c852b924c5f984f192d39705ddd287ea93bb73e3c5f95ba6da7e01f5",
                "4f6465206f6e2061204772656369616e2055726e",
                "8c490e5b0c7dbe0c6d2192484d2b7a0423b3b4544f2481095a99dbf238fb350f",
                "8a07563949fac6232936ed6f36c4fa735930ecdeaef6734e314aeac35a56fd0a",
                "5a8aa0d2476b28521588e0c704b14db82cdd4970d340d293a9576deaee9ec1c7",
                "8756e2580c07c1d2ffcb662f5fadc6d6ff13da85abd7adfecf984aaa102c1269",
                "",
                "",
                "550ee0b7ec1ea2532f2e2bac87040a4c",
                "2b855847756795a57229559a",
                "971ba65db526758ea30ae748cd769bc8d90579b62a037816057f24ce427416bd47c05ed1c2446ac8e19ec9ae79",
                "1aabf0ea393517daa48a9eaf44a886f5e059d455988a65ae8d66b3c017fc3722",
                {
                  "0df04ac640d34a56561419bab20a68e6b7331070208004f89c7b973f4c472e92",
                  "723c2c8f80e6b827e72bd8e80973a801a05514afe3d4bc46e82e505dceb953aa",
                  "38010c7d5d81093a11b55e2403a258e9a195bcf066817b332dd996b0a9bcbc9a",
                  "ebf6ab4c3186131de9b2c3c0bc3e2ad21dfcbc4efaf050cd0473f5b1535a8b6d",
                  "c4823eeb3efd2d5216b2d3b16e542bf57470dc9b9ea9af6bce85b151a3589d90",
                }
            },
            Params{
              Mode::Psk,
              NamedGroup::x25519,
              HashFunction::Sha256,
              CipherSuite::TLS_AES_128_GCM_SHA256,
              "9d4fe1809006b38854f056830b8900086f562207dce6010eadf23d2d5303cdf8",
              "4f6465206f6e2061204772656369616e2055726e",
              "e7d2b539792a48a24451303ccd0cfe77176b6cb06823c439edfd217458a1398a",
              "08d39d3e7f9b586341b6004dafba9679d2bd9340066edb247e3e919013efcd0f",
              "4b41ef269169090551fcea177ecdf622bca86d82298e21cd93119b804ccc5eab",
              "a5c85773bed3a831e7096f7df4ff5d1d8bac48fc97bfac366141efab91892a3a",
              "5db3b80a81cb63ca59470c83414ef70a",
              "456e6e796e20447572696e206172616e204d6f726961",
              "811e9b2d7a10f4f9d58786bf8a534ca6",
              "b79b0c5a8c3808e238b10411",
              "fb68f911b4e4033d1547f646ea30c9cee987fb4b4a8c30918e5de6e96de32fc63466f2fc05e09aeff552489741",
              "7e9ef6d537503f815d0eaf70550a1f8e9af12c1cccb76919aafe93535547c150",
              {
                "bd292b132fae00243851451c3f3a87e9e11c3293c14d61b114b7e12e07245ffd",
                "695de26bc9336caee01cb04826f6e224f4d2108066ab17fc18f0c993dce05f24",
                "c53f26ef1bf4f5fd5469d807c418a0e103d035c76ccdbc6afb5bc42b24968f6c",
                "8cea4a595dfe3de84644ca8ea7ea9401a345f0db29bb4beebc2c471afc602ec4",
                "e6313f12f6c2054c69018f273211c54fcf2439d90173392eaa34b4caac929068",
              },
            },
             Params{
              Mode::Psk,
              NamedGroup::x25519,
              HashFunction::Sha256,
              CipherSuite::TLS_AES_256_GCM_SHA384,
              "f228aa9be7ff1ebd78f52b8b00b7f15688935ce105e24df508ad27c68eea703a",
              "4f6465206f6e2061204772656369616e2055726e",
              "bf3981d4d9b43ea83365747e25d8ba71e14d21cca47e35e70b5311e1d48f8a0d",
              "8f65c9f75b4b774d36052dfac0bdd37a03f309b92c9a9ca47e903683be34d04d",
              "cb798ffb68e7b3db33913c365bf45a811fca8382522ac8815b12b26d3377a049",
              "4a9269e9db60008f5c7f3c7d39bb8c4923bc2f244b3ed9085191ef54cd10cf0c",
              "5db3b80a81cb63ca59470c83414ef70a",
              "456e6e796e20447572696e206172616e204d6f726961",
              "743493cb30aac02389f8db1be74b6a2f2e09f7b6fe337095b207bb3b750b1ace",
              "3b83c923d13310f21c71baba",
              "ad2a3e08e10413e7bdf9e89f2db169338fc68bcf8dc7bb073ca779024996de5922d338cf8407d34109cd2fdccf",
              "555a2c91cf21b146f7cdd2fce83dc165133b1896613c0e21d31583641b972967",
              {
                "c52ecbb65af1c6764ce7d2fd1131d5f050ee2f943a4fe56e9c855b44385b00cf",
                "42c5cf4f81152d05bacc9323e805eab8e429850dd029937c2c42f17ce7fea09b",
                "89d7f97327d51d61a4ac04b2507e51a977c8706bd932941f5acf1f542cfd034b",
                "581e3a66a1ad5309c3295825bc03407c7d9e34673e61aed2c543b47764577783",
                "599f10537288a9ec87d53c16aaa5881715061e6152a5b51b1e0433a396b38d10",
              },
            },
            Params{
              Mode::Psk,
              NamedGroup::x25519,
              HashFunction::Sha256,
              CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
              "95978c18311fc9e360209dd2cd10b2fcacf019ed25f7703cb2b4e4538558c13f",
              "4f6465206f6e2061204772656369616e2055726e",
              "4bfdb62b95ae2a1f29f20ea49e24aa2673e0d240c6e967f668f55ed5dee996dc",
              "f4639297e3305b03d34dd5d86522ddc6ba11a608a0003670a30734823cdd3763",
              "a6ab4e1bb782d580d837843089d65ebe271a0ee9b5a951777cecf1293c58c150",
              "c49b46ed73ecb7d3a6a3e44f54b8f00f9ab872b57dd79ded66d7231a14c64144",
              "5db3b80a81cb63ca59470c83414ef70a",
              "456e6e796e20447572696e206172616e204d6f726961",
              "396c06a52b39d0930594aa2c6944561cc1741f638557a12bef1c1cad349157c9",
              "baa4ecf96b5d6d536d0d7210",
              "f97ca72675b8199e8ffec65b4c200d901110b177b246f241b6f9716fb60b35b32a6d452675534b591e8141468a",
              "96c88d4b561a2fc98cbafc9cb7d98895c8962ba5d9693da550cf7ed115d9753f",
              {
                "735400cd9b9193daffe840f412074728ade6b1978e9ae27957aacd588dbd7c9e",
                "cf4e351e1943d171ff2d88726f18160086ecbec52a8151dba8cf5ba0737a6097",
                "8e23b44d4f23dd906d1c100580a670d171132c9786212c4ca2876a1541a84fae",
                "56252a940ece53d4013eb619b444ee1d019a08eec427ded2b6dbf24be624a4a0",
                "fc6cdca9ce8ab062401478ffd16ee1c07e2b15d7c781d4227f07c6043d937fad",
              },
            },
            Params{
              Mode::Base,
              NamedGroup::x25519,
              HashFunction::Sha256,
              CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
              "f995f043efe63c77ac333fbe6007240fd01006bac1b075d2807845afae89a19f",
              "4f6465206f6e2061204772656369616e2055726e",
              "5006a9a0f0138b9b5d577ed4a67c4f795aee8fc146ac63d7a4167765be3ad7dc",
              "716281787b035b2fee90455d951fa70b3db6cc92f13bedfd758c3487994b7020",
              "62139576dcbf9878ccd56262d1b28dbea897821c03370d81971513cc74aea3ff",
              "1ae26f65041b36ad69eb392c198bfd33df1c6ff17a910cb3e49db7506b6a4e7f",
              "",
              "",
              "1d5e71e2885ddadbcc479798cc65ea74d308f2a9e99c0cc7fe480adce66b5722",
              "8354a7fcfef97d4bbef6d24e",
              "fa4632a400962c98143e58450e75d879365359afca81a5f5b5997c6555647ec302045a80c57d3e2c2abe7e1ced",
              "3ef38fcad3a0bc7fca8ba8ccea4a556db32320bca35140cb9ee6ec6dd801b602",
              {
                "22bbe971392c685b55e13544cdaf976f36b89dc1dbe1296c2884971a5aa9e331",
                "5c0fa72053a2622d8999b726446db9ef743e725e2cb040afac2d83eae0d41981",
                "72b0f9999fd37ac2b948a07dadd01132587501a5a9460d596c1f7383299a2442",
                "73d2308ed5bdd63aacd236effa0db2d3a30742b6293a924d95a372e76d90486b",
                "d4f8878dbc471935e86cdee08746e53837bbb4b6013003bebb0bc1cc3e074085",
              },
            }
    ));
// clang-format on

} // namespace test
} // namespace hpke
} // namespace fizz
