/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <fizz/record/Extensions.h>
#include <fizz/record/test/ClientHelloTestData.h>
#include <folly/String.h>

using namespace folly;

static const std::string encodedShlo =
    "03039f2bfbe752cb49bc82303dd32a80cf60483a38e44bfb695ebd0280bcc1c70c5b00130100002e00330024001d00208db235a330ee184b953a981ecfb23b05380768ed12050ec2f0ec62b74ef8f835002b00020304";

static const std::string encodedEoed;

static const std::string encodedEncryptedExtensions =
    "001c000a00140012001d0017001800190100010101020103010400000000";

static const std::string encodedCertificate =
    "000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000";

static const std::string encodedCertVerify =
    "080400805db9706f9bd41ab01be55f75b136cb89dda63dc6e4510e40c7203cb87f4eba2b122644018640641bde97e03d4caa1d670371b8bf81374d5126f88df68b87ef6c706cf9c0ee04063d8e65cb403433fb006c800e307b79b3a51fbae6089c2f3988ddfe04a760902e0a2141046054bdf807cf48cd3ce83f58a149ba35b7ff6c2f2a";

static const std::string nst =
    "0002a300d0a8dc290000924e535321db0251332a66d4efd3b0285509fd8a26b801211c72f5f9012b8a6f35005069950156fc02abe56744e7c7d2798675e8372cbba2a93e2436bcd3dbac7662e64e187379bec081051957c0da819d44fafb13d833752c7340a32df5e133e3717566ac66b4cc417a4d0afaa64493997dba0cd6e601bc11a4ce5506236c2c4094d1ea2329d1756ac32783ef158e91a92c440008002e000400020000";

static const std::string encodedKeyUpdate = "00";

static const std::string encodedCertRequest = "00000a000d0006000406030807";

static const std::string encodedCompressedCertificate =
    "000100face000009666f6f62617262617a";

namespace fizz {
namespace test {

class HandshakeTypesTest : public testing::Test {
 protected:
  template <class T>
  T decodeHex(std::string_view hex) {
    auto data = unhexlify(hex);
    auto buf = IOBuf::copyBuffer(data.data(), data.size());
    T decoded;
    Error err;
    FIZZ_THROW_ON_ERROR(decode<T>(decoded, err, std::move(buf)), err);
    return decoded;
  }

  template <class T>
  std::string encodeHex(T&& msg) {
    Buf buf;
    Error err;
    FIZZ_THROW_ON_ERROR(encode(buf, err, std::forward<T>(msg)), err);
    auto str = buf->template to<std::string>();
    return hexlify(str);
  }
};

TEST_F(HandshakeTypesTest, ChloEncodeDecode) {
  auto clientHello = decodeHex<ClientHello>(kFirefoxClientHello);

  folly::Optional<SignatureAlgorithms> sigAlgs;
  Error err;
  EXPECT_EQ(
      getExtension(sigAlgs, err, clientHello.extensions), Status::Success);
  ASSERT_TRUE(sigAlgs);
  const auto& schemes = sigAlgs->supported_signature_algorithms;
  ASSERT_EQ(11, schemes.size());
  ASSERT_FALSE(
      schemes.end() ==
      std::find(
          schemes.begin(),
          schemes.end(),
          SignatureScheme::ecdsa_secp256r1_sha256));

  folly::Optional<SupportedGroups> groups;
  EXPECT_EQ(getExtension(groups, err, clientHello.extensions), Status::Success);
  const auto& groupNames = groups->named_group_list;
  ASSERT_EQ(3, groupNames.size());
  ASSERT_FALSE(
      groupNames.end() ==
      std::find(groupNames.begin(), groupNames.end(), NamedGroup::secp256r1));

  folly::Optional<ClientKeyShare> clientShares;
  EXPECT_EQ(
      getExtension(clientShares, err, clientHello.extensions), Status::Success);
  ASSERT_TRUE(clientShares);
  ASSERT_EQ(2, clientShares->client_shares.size());

  folly::Optional<ClientPresharedKey> psk;
  EXPECT_EQ(getExtension(psk, err, clientHello.extensions), Status::Success);
  ASSERT_FALSE(psk);
  folly::Optional<ClientEarlyData> earlyData;
  EXPECT_EQ(
      getExtension(earlyData, err, clientHello.extensions), Status::Success);
  ASSERT_FALSE(earlyData);
  folly::Optional<Cookie> cookie;
  EXPECT_EQ(getExtension(cookie, err, clientHello.extensions), Status::Success);
  ASSERT_FALSE(cookie);

  auto reencoded = encodeHex(std::move(clientHello));
  EXPECT_EQ(kFirefoxClientHello, reencoded);
}

TEST_F(HandshakeTypesTest, SSL3ChloDecode) {
  auto clientHello = decodeHex<ClientHello>(kSsl3ClientHello);
  EXPECT_TRUE(clientHello.extensions.empty());
}

TEST_F(HandshakeTypesTest, ChloDecidePsk) {
  auto clientHello = decodeHex<ClientHello>(kPskClientHello);

  size_t binderLength;
  Error err;
  EXPECT_EQ(getBinderLength(binderLength, err, clientHello), Status::Success);
  EXPECT_EQ(35, binderLength);
}

TEST_F(HandshakeTypesTest, ChloEncodeCopy) {
  auto clientHello = decodeHex<ClientHello>(kFirefoxClientHello);
  EXPECT_EQ(encodeHex(clientHello), kFirefoxClientHello);
  EXPECT_EQ(encodeHex(clientHello), kFirefoxClientHello);
}

TEST_F(HandshakeTypesTest, NstEncodeDecode) {
  auto ticket = decodeHex<NewSessionTicket>(nst);

  EXPECT_EQ(ticket.ticket_lifetime, 0x0002a300);
  EXPECT_EQ(ticket.ticket_age_add, 0xd0a8dc29);
  EXPECT_TRUE(ticket.ticket_nonce->empty());
  EXPECT_EQ(ticket.ticket->computeChainDataLength(), 146);

  auto reencoded = encodeHex(std::move(ticket));
  EXPECT_EQ(nst, reencoded);
}

bool extensionsMatch(const Extension& expected, const Extension& actual) {
  if (expected.extension_type != actual.extension_type) {
    return false;
  }
  return folly::IOBufEqualTo()(
      *expected.extension_data, *actual.extension_data);
}

TEST_F(HandshakeTypesTest, EncodeAndDecodeSigAlgs) {
  auto clientHello = decodeHex<ClientHello>(kFirefoxClientHello);
  folly::Optional<SignatureAlgorithms> sigAlgs;
  Error err;
  EXPECT_EQ(
      getExtension(sigAlgs, err, clientHello.extensions), Status::Success);
  ASSERT_TRUE(sigAlgs);
  Extension ext;
  EXPECT_EQ(encodeExtension(ext, err, *sigAlgs), Status::Success);
  auto original = findExtension(
      clientHello.extensions, ExtensionType::signature_algorithms);
  EXPECT_TRUE(extensionsMatch(*original, ext));
}

TEST_F(HandshakeTypesTest, EncodeAndDecodeClientKeyShare) {
  auto clientHello = decodeHex<ClientHello>(kFirefoxClientHello);
  folly::Optional<ClientKeyShare> share;
  Error err;
  EXPECT_EQ(getExtension(share, err, clientHello.extensions), Status::Success);
  ASSERT_TRUE(share);
  Extension ext;
  EXPECT_EQ(encodeExtension(ext, err, *share), Status::Success);
  auto original =
      findExtension(clientHello.extensions, ExtensionType::key_share);
  EXPECT_TRUE(extensionsMatch(*original, ext));
}

TEST_F(HandshakeTypesTest, EncodeAndDecodeServerHello) {
  auto shlo = decodeHex<ServerHello>(encodedShlo);
  EXPECT_EQ(shlo.legacy_version, ProtocolVersion::tls_1_2);
  EXPECT_EQ(shlo.random.front(), 0x9f);
  EXPECT_EQ(shlo.random.back(), 0x5b);
  EXPECT_EQ(shlo.cipher_suite, CipherSuite::TLS_AES_128_GCM_SHA256);
  EXPECT_EQ(shlo.extensions.size(), 2);
  folly::Optional<ServerKeyShare> serverKeyShare;
  Error err;
  EXPECT_EQ(
      getExtension(serverKeyShare, err, shlo.extensions), Status::Success);
  EXPECT_TRUE(serverKeyShare.has_value());
  folly::Optional<ServerSupportedVersions> serverVersions;
  EXPECT_EQ(
      getExtension(serverVersions, err, shlo.extensions), Status::Success);
  EXPECT_TRUE(serverVersions.has_value());
  auto reencoded = encodeHex(std::move(shlo));
  EXPECT_EQ(reencoded, encodedShlo);
}

TEST_F(HandshakeTypesTest, EncodeAndDecodeEndOfEarlyData) {
  auto eoed = decodeHex<EndOfEarlyData>(encodedEoed);
  auto reencoded = encodeHex(std::move(eoed));
  EXPECT_EQ(reencoded, encodedEoed);
}

TEST_F(HandshakeTypesTest, EncodeAndDecodeEncryptedExtensions) {
  auto ee = decodeHex<EncryptedExtensions>(encodedEncryptedExtensions);
  EXPECT_EQ(ee.extensions.size(), 2);
  folly::Optional<SupportedGroups> supportedGroups;
  Error err;
  EXPECT_EQ(getExtension(supportedGroups, err, ee.extensions), Status::Success);
  EXPECT_TRUE(supportedGroups.has_value());
  auto reencoded = encodeHex(std::move(ee));
  EXPECT_EQ(reencoded, encodedEncryptedExtensions);
}

TEST_F(HandshakeTypesTest, EncodeAndDecodedCertificate) {
  auto cert = decodeHex<CertificateMsg>(encodedCertificate);
  EXPECT_EQ(cert.certificate_request_context->computeChainDataLength(), 0);
  EXPECT_EQ(cert.certificate_list.size(), 1);
  EXPECT_EQ(cert.certificate_list[0].cert_data->computeChainDataLength(), 432);
  EXPECT_TRUE(cert.certificate_list[0].extensions.empty());
  auto reencoded = encodeHex(std::move(cert));
  EXPECT_EQ(reencoded, encodedCertificate);
}

TEST_F(HandshakeTypesTest, EncodedAndDecodeCertificateVerify) {
  auto verify = decodeHex<CertificateVerify>(encodedCertVerify);
  EXPECT_EQ(verify.algorithm, SignatureScheme::rsa_pss_sha256);
  EXPECT_EQ(verify.signature->computeChainDataLength(), 128);
  auto reencoded = encodeHex(std::move(verify));
  EXPECT_EQ(reencoded, encodedCertVerify);
}

TEST_F(HandshakeTypesTest, EncodedAndDecodeKeyUpdated) {
  auto keyUpdate = decodeHex<KeyUpdate>(encodedKeyUpdate);
  EXPECT_EQ(keyUpdate.request_update, KeyUpdateRequest::update_not_requested);
  auto reencoded = encodeHex(std::move(keyUpdate));
  EXPECT_EQ(reencoded, encodedKeyUpdate);
}

TEST_F(HandshakeTypesTest, EncodedAndDecodeCertificateRequest) {
  auto cr = decodeHex<CertificateRequest>(encodedCertRequest);
  EXPECT_TRUE(cr.certificate_request_context->empty());
  EXPECT_EQ(cr.extensions.size(), 1);
  folly::Optional<SignatureAlgorithms> sigAlgs;
  Error err;
  EXPECT_EQ(getExtension(sigAlgs, err, cr.extensions), Status::Success);
  EXPECT_TRUE(sigAlgs.has_value());
  auto reencoded = encodeHex(std::move(cr));
  EXPECT_EQ(reencoded, encodedCertRequest);
}

TEST_F(HandshakeTypesTest, EncodeAndDecodeCompressedCertificate) {
  auto cc = decodeHex<CompressedCertificate>(encodedCompressedCertificate);
  EXPECT_EQ(cc.algorithm, CertificateCompressionAlgorithm::zlib);
  EXPECT_EQ(cc.uncompressed_length, 0x00face);
  EXPECT_EQ(
      StringPiece(cc.compressed_certificate_message->coalesce()),
      StringPiece("foobarbaz"));
  auto reencoded = encodeHex(std::move(cc));
  EXPECT_EQ(reencoded, encodedCompressedCertificate);
}
} // namespace test
} // namespace fizz
