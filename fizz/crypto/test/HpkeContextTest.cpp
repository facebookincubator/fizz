/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>
#include <fizz/crypto/HpkeContext.h>
#include <fizz/crypto/aead/AESGCM128.h>
#include <fizz/crypto/aead/AESGCM256.h>
#include <fizz/crypto/aead/AESOCB128.h>
#include <fizz/crypto/aead/ChaCha20Poly1305.h>
#include <fizz/crypto/aead/test/TestUtil.h>
#include <fizz/crypto/Sha256.h>
#include <fizz/record/Types.h>

using namespace fizz::test;

namespace fizz {
namespace hpke {
namespace test {

const folly::StringPiece kExportSecret = folly::StringPiece(
  folly::unhexlify("60f5fe76e2699f98c19eab82fecf330b990ac32694a8e40e598e2326d0e29150"));
constexpr size_t kHeadroom = 10;
constexpr folly::Range kPrefix = folly::Range("HPKE-05 ");

struct Params {
  std::string key;
  std::string iv;
  std::string aad;
  std::string plaintext;
  std::string ciphertext;
  CipherSuite cipher;
};

class HpkeContextTest : public ::testing::TestWithParam<Params> {};

std::unique_ptr<Aead> getCipher(const Params& params) {
  std::unique_ptr<Aead> cipher;
  switch (params.cipher) {
    case CipherSuite::TLS_AES_128_GCM_SHA256:
      cipher = OpenSSLEVPCipher::makeCipher<AESGCM128>();
      break;
    case CipherSuite::TLS_AES_256_GCM_SHA384:
      cipher = OpenSSLEVPCipher::makeCipher<AESGCM256>();
      break;
    case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
      cipher = OpenSSLEVPCipher::makeCipher<ChaCha20Poly1305>();
      break;
    case CipherSuite::TLS_AES_128_OCB_SHA256_EXPERIMENTAL:
      cipher = OpenSSLEVPCipher::makeCipher<AESOCB128>();
      break;
    default:
      throw std::runtime_error("Invalid cipher");
  }

  TrafficKey trafficKey;
  trafficKey.key = toIOBuf(params.key);
  trafficKey.iv = toIOBuf(params.iv);
  cipher->setKey(std::move(trafficKey));
  cipher->setEncryptedBufferHeadroom(kHeadroom);
  return cipher;
}

TEST_P(HpkeContextTest, TestContext) {
  auto testParam = GetParam();
  HpkeContext encryptContext(getCipher(testParam), kExportSecret,
    std::make_unique<fizz::hpke::Hkdf>(kPrefix, std::make_unique<HkdfImpl>(HkdfImpl::create<Sha256>())));
  auto gotCiphertext = encryptContext.seal(toIOBuf(testParam.aad).get(), toIOBuf(testParam.plaintext));
  EXPECT_TRUE(folly::IOBufEqualTo()(gotCiphertext, toIOBuf(testParam.ciphertext)));

  HpkeContext decryptContext(getCipher(testParam), kExportSecret,
    std::make_unique<fizz::hpke::Hkdf>(kPrefix, std::make_unique<HkdfImpl>(HkdfImpl::create<Sha256>())));
  auto gotPlaintext = decryptContext.open(toIOBuf(testParam.aad).get(), std::move(gotCiphertext));
  EXPECT_TRUE(folly::IOBufEqualTo()(gotPlaintext, toIOBuf(testParam.plaintext)));
}

/***
 * Test vectors sourced from HPKE IETF draft and existing tests.
 * https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/580119bb7bb45fd09a1079b920f8ef257f901309/test-vectors.json
 */
// clang-format off

INSTANTIATE_TEST_CASE_P(
    TestVectors,
    HpkeContextTest,
    ::testing::
        Values(
            Params{
                "f0529818bc7e87857fd38eeca1a47020",
                "4bbcb168c8486e04b9382642",
                "436f756e742d30",
                "4265617574792069732074727574682c20747275746820626561757479",
                "9076d402a8bacf1721ce194185de331c014c55dd801ae92aa63017a1f0c0dff615d4bcbc03d22f6d635e89b4c2",
                CipherSuite::TLS_AES_128_GCM_SHA256},
            Params{
                "550ee0b7ec1ea2532f2e2bac87040a4c",
                "2b855847756795a57229559a",
                "436f756e742d30",
                "4265617574792069732074727574682c20747275746820626561757479",
                "971ba65db526758ea30ae748cd769bc8d90579b62a037816057f24ce427416bd47c05ed1c2446ac8e19ec9ae79",
                CipherSuite::TLS_AES_128_GCM_SHA256},
            Params{
                "E3C08A8F06C6E3AD95A70557B23F75483CE33021A9C72B7025666204C69C0B72",
                "12153524C0895E81B2C28465",
                "D609B1F056637A0D46DF998D88E52E00B2C2846512153524C0895E81",
                "08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A0002",
                "E2006EB42F5277022D9B19925BC419D7A592666C925FE2EF718EB4E308EFEAA7C5273B394118860A5BE2A97F56AB78365CA597CDBB3EDB8D1A1151EA0AF7B436",
                CipherSuite::TLS_AES_256_GCM_SHA384},
            Params{
                "9a97f65b9b4c721b960a672145fca8d4e32e67f9111ea979ce9c4826806aeee6",
                "000000003de9c0da2bd7f91e",
                "",
                "",
                "5a6e21f4ba6dbee57380e79e79c30def",
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256},
            Params{
                "000102030405060708090A0B0C0D0E0F",
                "000102030405060708090A0B",
                "0001020304050607",
                "0001020304050607",
                "92B657130A74B85A16DC76A46D47E1EAD537209E8A96D14E",
                CipherSuite::TLS_AES_128_OCB_SHA256_EXPERIMENTAL}
    ));
// clang-format on

} // namespace test
} // namespace hpke
} // namespace fizz
