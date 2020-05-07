/*
 *  Copyright (c) 2019-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <fizz/crypto/Utils.h>
#include <fizz/crypto/test/TestUtil.h>
#include <fizz/extensions/delegatedcred/PeerDelegatedCredential.h>

using namespace folly;

using namespace testing;
using namespace fizz::test;

namespace fizz {
namespace extensions {
namespace test {

StringPiece kCredCert = R"(
-----BEGIN CERTIFICATE-----
MIIB6TCCAY+gAwIBAgIJAKlQpSahHUIWMAoGCCqGSM49BAMCMEIxCzAJBgNVBAYT
AlhYMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxHDAaBgNVBAoME0RlZmF1bHQgQ29t
cGFueSBMdGQwHhcNMTkwNTI0MTk1MjU3WhcNMjAwNTIzMTk1MjU3WjBCMQswCQYD
VQQGEwJYWDEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQKDBNEZWZhdWx0
IENvbXBhbnkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8RC+4O48vtBh
JhSn3/wuzfygo/AQGGNMavAb5YnZpy6rMaY9UG3OlFfkRRmvETlbn3CXD0klXuc/
wYCKoVXGYqNuMGwwHQYDVR0OBBYEFC892QWimVBjX1AODjjL+SqTN1meMB8GA1Ud
IwQYMBaAFC892QWimVBjX1AODjjL+SqTN1meMAwGA1UdEwQFMAMBAf8wCwYDVR0P
BAQDAgHmMA8GCSsGAQQBgtpLLAQCBQAwCgYIKoZIzj0EAwIDSAAwRQIhAPoWbJWf
Fw+uQ6c27kul/uTNIF4GOEUCmCWVvc6qkhHVAiBKTBrUi8h8g/U0yQ4prS0/wfkw
FghrPnYCODq235mY2A==
-----END CERTIFICATE-----
)";

// Credential generated using example BoringSSL app at P64740349
StringPiece kDelegatedCred{
    "001cff98040300005b3059301306072a8648ce3d020106082a8648ce3d030107"
    "03420004db94b7b305323633ccc5a5f12a3b07c22bbf86e5d531ed94d09c5bfe"
    "860b72e5dc73b8267729f34150a6422cbdc87484a535125ff3a02a03372c0969"
    "3abf0505040300473045022016656f399fa5247dbbd14a682062edd8606a59bc"
    "fe822dcf68f3c172934f17e1022100e7d39ad69b44097a74911d31230329ac07"
    "20e55a38e6f59fb6c10490c185f4c1"};

StringPiece kVerifyBuffer{
    "8bc8098c4f45d1c9ea354955f5c99a50b442c6ab8b58c6623582b60ddc8c2ef2"};

StringPiece kSignature{
    "304602210087826312e48d3334d46b5c72fdf8b53e03a9f9ca65ebe1485804a3"
    "bcf2b08a87022100a963412a349e5d1b763e722103a6c0c7e7ec577240b0bb05"
    "b323cf17b4705d80"};

class PeerDelegatedCredentialTest : public Test {
 public:
  void SetUp() override {
    CryptoUtils::init();
  }

  Buf toBuf(const StringPiece& hex) {
    auto data = unhexlify(hex);
    return IOBuf::copyBuffer(data.data(), data.size());
  }

  DelegatedCredential getCredential() {
    Extension ext;
    ext.extension_type = ExtensionType::delegated_credential;
    ext.extension_data = toBuf(kDelegatedCred);
    std::vector<Extension> exts;
    exts.push_back(std::move(ext));
    return *getExtension<DelegatedCredential>(exts);
  }

  void expectThrows(std::function<void()> f, std::string errorStr) {
    std::string what;
    try {
      f();
    } catch (const FizzException& e) {
      what = e.what();
    }

    EXPECT_THAT(what, HasSubstr(errorStr));
  }
};

TEST_F(PeerDelegatedCredentialTest, TestCredentialVerify) {
  auto cred = getCredential();
  auto cert = getCert(kCredCert);
  auto pubKeyRange = cred.public_key->coalesce();
  auto addr = pubKeyRange.data();
  folly::ssl::EvpPkeyUniquePtr pubKey(
      d2i_PUBKEY(nullptr, &addr, pubKeyRange.size()));
  auto peerCred = std::make_shared<PeerDelegatedCredential<KeyType::P256>>(
      std::move(cert), std::move(pubKey), std::move(cred));

  peerCred->verify(
      SignatureScheme::ecdsa_secp256r1_sha256,
      CertificateVerifyContext::Server,
      toBuf(kVerifyBuffer)->coalesce(),
      toBuf(kSignature)->coalesce());
}

TEST_F(PeerDelegatedCredentialTest, TestCredentialVerifyWrongCert) {
  auto cred = getCredential();
  auto cert = getCert(kP256Certificate);
  auto pubKeyRange = cred.public_key->coalesce();
  auto addr = pubKeyRange.data();
  folly::ssl::EvpPkeyUniquePtr pubKey(
      d2i_PUBKEY(nullptr, &addr, pubKeyRange.size()));
  auto peerCred = std::make_shared<PeerDelegatedCredential<KeyType::P256>>(
      std::move(cert), std::move(pubKey), std::move(cred));

  expectThrows(
      [&]() {
        peerCred->verify(
            SignatureScheme::ecdsa_secp256r1_sha256,
            CertificateVerifyContext::Server,
            toBuf(kVerifyBuffer)->coalesce(),
            toBuf(kSignature)->coalesce());
      },
      "failed to verify signature on credential");
}

TEST_F(PeerDelegatedCredentialTest, TestCredentialVerifyWrongAlgo) {
  auto cred = getCredential();
  auto cert = getCert(kCredCert);
  auto pubKeyRange = cred.public_key->coalesce();
  auto addr = pubKeyRange.data();
  folly::ssl::EvpPkeyUniquePtr pubKey(
      d2i_PUBKEY(nullptr, &addr, pubKeyRange.size()));
  auto peerCred = std::make_shared<PeerDelegatedCredential<KeyType::P256>>(
      std::move(cert), std::move(pubKey), std::move(cred));

  // Should fail early due to mismatch with credential
  expectThrows(
      [&]() {
        peerCred->verify(
            SignatureScheme::ecdsa_secp521r1_sha512,
            CertificateVerifyContext::Server,
            toBuf(kVerifyBuffer)->coalesce(),
            toBuf(kSignature)->coalesce());
      },
      "certificate verify didn't use credential's algorithm");
}

TEST_F(PeerDelegatedCredentialTest, TestCredentialVerifyBitFlip) {
  auto cred = getCredential();
  auto cert = getCert(kCredCert);
  auto pubKeyRange = cred.public_key->coalesce();
  auto addr = pubKeyRange.data();
  folly::ssl::EvpPkeyUniquePtr pubKey(
      d2i_PUBKEY(nullptr, &addr, pubKeyRange.size()));
  auto peerCred = std::make_shared<PeerDelegatedCredential<KeyType::P256>>(
      std::move(cert), std::move(pubKey), std::move(cred));

  auto sig = toBuf(kSignature);
  sig->writableData()[1] ^= 0x20;
  EXPECT_THROW(
      peerCred->verify(
          SignatureScheme::ecdsa_secp256r1_sha256,
          CertificateVerifyContext::Server,
          toBuf(kVerifyBuffer)->coalesce(),
          sig->coalesce()),
      std::runtime_error);
}

TEST_F(PeerDelegatedCredentialTest, TestCredentialVerifySizeMismatch) {
  auto cred = getCredential();
  auto cert = getCert(kCredCert);
  auto pubKeyRange = cred.public_key->coalesce();
  auto addr = pubKeyRange.data();
  folly::ssl::EvpPkeyUniquePtr pubKey(
      d2i_PUBKEY(nullptr, &addr, pubKeyRange.size()));
  auto peerCred = std::make_shared<PeerDelegatedCredential<KeyType::P256>>(
      std::move(cert), std::move(pubKey), std::move(cred));

  auto sig = toBuf(kSignature);
  sig->prependChain(IOBuf::copyBuffer("0"));
  EXPECT_THROW(
      peerCred->verify(
          SignatureScheme::ecdsa_secp256r1_sha256,
          CertificateVerifyContext::Server,
          toBuf(kVerifyBuffer)->coalesce(),
          sig->coalesce()),
      std::runtime_error);
}

} // namespace test
} // namespace extensions
} // namespace fizz
