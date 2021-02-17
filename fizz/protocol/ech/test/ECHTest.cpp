/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */
#include <vector>

#include <fizz/protocol/ech/ECHExtensions.h>
#include <fizz/protocol/ech/test/TestUtil.h>
#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

namespace fizz {
namespace ech {
namespace test {

const std::array<unsigned char, 16> kTestECHNonce = {
    0xCF,
    0x21,
    0xAD,
    0x74,
    0xE5,
    0x9A,
    0x61,
    0x11,
    0xBE,
    0x1D,
    0x8C,
    0x02,
    0x1E,
    0x65,
    0xB8,
    0x91};
folly::StringPiece kECHNonceExtensionData{"cf21ad74e59a6111be1d8c021e65b891"};
folly::StringPiece kExtensionData{
    "0001000100146b546573745265636f7264446967657374537472000b6b54657374456e6353747200126563685f636f6e6669675f636f6e74656e74"};
folly::StringPiece kTestClientHelloInnerStr{
    "6563685f636f6e6669675f636f6e74656e74"};
folly::StringPiece kTestEncStr{"6b54657374456e63537472"};
folly::StringPiece kTestRecordDigestStr{
    "6b546573745265636f7264446967657374537472"};
folly::StringPiece kClientECHExtensionData{
    "000100010009636f6e6669675f69640003656e6300077061796c6f6164"};

Buf getBuf(folly::StringPiece hex) {
  auto data = unhexlify(hex);
  return folly::IOBuf::copyBuffer(data.data(), data.size());
}

TEST(ECHTest, TestConfigContentEncodeDecodeV7) {
  // Encode config content
  std::unique_ptr<folly::IOBuf> echConfigContentBuf =
      encode<ECHConfigContentDraft>(getECHConfigContent());

  // Decode config content
  folly::io::Cursor cursor(echConfigContentBuf.get());
  auto gotEchConfigContent = decode<ECHConfigContentDraft>(cursor);

  // Check decode(encode(content)) = content
  auto expectedEchConfigContent = getECHConfigContent();
  EXPECT_TRUE(folly::IOBufEqualTo()(
      gotEchConfigContent.public_name, expectedEchConfigContent.public_name));
  EXPECT_TRUE(folly::IOBufEqualTo()(
      gotEchConfigContent.public_key, expectedEchConfigContent.public_key));
  EXPECT_EQ(gotEchConfigContent.kem_id, expectedEchConfigContent.kem_id);
  EXPECT_EQ(
      gotEchConfigContent.cipher_suites.size(),
      expectedEchConfigContent.cipher_suites.size());
  EXPECT_EQ(
      gotEchConfigContent.maximum_name_length,
      expectedEchConfigContent.maximum_name_length);
  EXPECT_EQ(gotEchConfigContent.extensions.size(), 1);
  auto ext = getExtension<Cookie>(gotEchConfigContent.extensions);
  EXPECT_EQ(
      folly::StringPiece(ext->cookie->coalesce()),
      folly::StringPiece("cookie"));
}

TEST(ECHTest, TestConfigContentEncodeDecodeV8) {
  // Encode config contents
  std::unique_ptr<folly::IOBuf> echConfigContentBuf =
      encode<ECHConfigContentDraft>(getECHConfigContent());

  // Decode config content
  folly::io::Cursor cursor(echConfigContentBuf.get());
  auto gotEchConfigContent = decode<ECHConfigContentDraft>(cursor);

  // Check decode(encode(content)) = content
  auto expectedEchConfigContent = getECHConfigContent();
  EXPECT_TRUE(folly::IOBufEqualTo()(
      gotEchConfigContent.public_name, expectedEchConfigContent.public_name));
  EXPECT_TRUE(folly::IOBufEqualTo()(
      gotEchConfigContent.public_key, expectedEchConfigContent.public_key));
  EXPECT_EQ(gotEchConfigContent.kem_id, expectedEchConfigContent.kem_id);
  EXPECT_EQ(
      gotEchConfigContent.cipher_suites.size(),
      expectedEchConfigContent.cipher_suites.size());
  EXPECT_EQ(
      gotEchConfigContent.maximum_name_length,
      expectedEchConfigContent.maximum_name_length);
  EXPECT_EQ(gotEchConfigContent.extensions.size(), 1);
  auto ext = getExtension<Cookie>(gotEchConfigContent.extensions);
  EXPECT_EQ(
      folly::StringPiece(ext->cookie->coalesce()),
      folly::StringPiece("cookie"));
}

TEST(ECHTest, TestECHConfigEncodeDecode) {
  // Encode ECH config
  ECHConfig echConfig;
  echConfig.length = 1;
  echConfig.version = ECHVersion::V7;
  echConfig.ech_config_content =
      encode<ECHConfigContentDraft>(getECHConfigContent());
  std::unique_ptr<folly::IOBuf> encodedBuf =
      encode<ECHConfig>(std::move(echConfig));

  // Decode ECH config
  folly::io::Cursor cursor(encodedBuf.get());
  auto gotECHConfig = decode<ECHConfig>(cursor);

  // Check decode(encode(config)) = config
  EXPECT_EQ(gotECHConfig.length, 1);
  EXPECT_EQ(gotECHConfig.version, ECHVersion::V7);
  EXPECT_TRUE(folly::IOBufEqualTo()(
      gotECHConfig.ech_config_content,
      encode<ECHConfigContentDraft>(getECHConfigContent())));
}

TEST(ECHTest, TestECHExtensionEncode) {
  EncryptedClientHello ech;
  ech.suite =
      ECHCipherSuite{hpke::KDFId::Sha256, hpke::AeadId::TLS_AES_128_GCM_SHA256};
  ech.record_digest = getBuf(kTestRecordDigestStr);
  ech.enc = getBuf(kTestEncStr);
  ech.encrypted_ch = getBuf(kTestClientHelloInnerStr);

  Extension encoded = encodeExtension<ech::EncryptedClientHello>(ech);

  EXPECT_EQ(encoded.extension_type, ExtensionType::encrypted_client_hello);
  EXPECT_TRUE(folly::IOBufEqualTo()(
      encoded.extension_data,
      folly::IOBuf::copyBuffer(folly::unhexlify(kExtensionData))));
}

TEST(ECHTest, TestClientECHEncode) {
  ClientECH ech;
  ech.cipher_suite =
      ECHCipherSuite{hpke::KDFId::Sha256, hpke::AeadId::TLS_AES_128_GCM_SHA256};
  ech.config_id = folly::IOBuf::copyBuffer("config_id");
  ech.enc = folly::IOBuf::copyBuffer("enc");
  ech.payload = folly::IOBuf::copyBuffer("payload");

  Extension encoded = encodeExtension<ech::ClientECH>(ech);

  EXPECT_EQ(encoded.extension_type, ExtensionType::encrypted_client_hello);
  // This was captured as the expected output from generating the result.
  EXPECT_TRUE(folly::IOBufEqualTo()(
      encoded.extension_data,
      folly::IOBuf::copyBuffer(folly::unhexlify(kClientECHExtensionData))));
}

TEST(ECHTest, TestECHExtensionDecode) {
  Extension e;
  e.extension_type = ExtensionType::encrypted_client_hello;
  e.extension_data = folly::IOBuf::copyBuffer(folly::unhexlify(kExtensionData));
  std::vector<Extension> vec;
  vec.push_back(std::move(e));
  auto ech = getExtension<EncryptedClientHello>(vec);

  EXPECT_EQ(ech->suite.kdf_id, hpke::KDFId::Sha256);
  EXPECT_TRUE(
      folly::IOBufEqualTo()(ech->record_digest, getBuf(kTestRecordDigestStr)));
  EXPECT_TRUE(folly::IOBufEqualTo()(ech->enc, getBuf(kTestEncStr)));
  EXPECT_TRUE(folly::IOBufEqualTo()(
      ech->encrypted_ch, getBuf(kTestClientHelloInnerStr)));
}

TEST(ECHTest, TestClientECHDecode) {
  Extension e;
  e.extension_type = ExtensionType::encrypted_client_hello;
  e.extension_data =
      folly::IOBuf::copyBuffer(folly::unhexlify(kClientECHExtensionData));
  std::vector<Extension> vec;
  vec.push_back(std::move(e));
  auto ech = getExtension<ClientECH>(vec);

  EXPECT_EQ(ech->cipher_suite.kdf_id, hpke::KDFId::Sha256);
  EXPECT_TRUE(folly::IOBufEqualTo()(
      ech->config_id, folly::IOBuf::copyBuffer("config_id")));
  EXPECT_TRUE(folly::IOBufEqualTo()(ech->enc, folly::IOBuf::copyBuffer("enc")));
  EXPECT_TRUE(
      folly::IOBufEqualTo()(ech->payload, folly::IOBuf::copyBuffer("payload")));
}

TEST(ECHTest, TestECHNonceEncode) {
  ECHNonce echNonce;
  echNonce.nonce = kTestECHNonce;
  Extension encoded = encodeExtension<ech::ECHNonce>(echNonce);

  EXPECT_EQ(encoded.extension_type, ExtensionType::ech_nonce);
  EXPECT_TRUE(folly::IOBufEqualTo()(
      encoded.extension_data,
      folly::IOBuf::copyBuffer(folly::unhexlify(kECHNonceExtensionData))));
}

TEST(ECHTest, TestECHNonceDecode) {
  Extension e;
  e.extension_type = ExtensionType::ech_nonce;
  e.extension_data =
      folly::IOBuf::copyBuffer(folly::unhexlify(kECHNonceExtensionData));
  std::vector<Extension> vec;
  vec.push_back(std::move(e));
  auto echNonce = getExtension<ECHNonce>(vec);

  EXPECT_EQ(echNonce->nonce.size(), 16);
  EXPECT_EQ(echNonce->nonce, kTestECHNonce);
}

} // namespace test
} // namespace ech
} // namespace fizz
