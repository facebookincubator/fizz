/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <fizz/client/AsyncFizzClient.h>
#include <fizz/client/test/Mocks.h>
#include <fizz/crypto/Utils.h>
#include <fizz/crypto/aead/AESGCM128.h>
#include <fizz/crypto/aead/OpenSSLEVPCipher.h>
#include <fizz/crypto/test/TestUtil.h>
#include <fizz/extensions/tokenbinding/TokenBindingClientExtension.h>
#include <fizz/extensions/tokenbinding/TokenBindingContext.h>
#include <fizz/extensions/tokenbinding/TokenBindingServerExtension.h>
#include <fizz/protocol/ZlibCertificateCompressor.h>
#include <fizz/protocol/ZlibCertificateDecompressor.h>
#include <fizz/protocol/test/Matchers.h>
#include <fizz/protocol/test/Utilities.h>
#include <fizz/server/AsyncFizzServer.h>
#include <fizz/server/CookieTypes.h>
#include <fizz/server/TicketTypes.h>
#include <fizz/server/test/Mocks.h>
#include <fizz/test/LocalTransport.h>

using namespace folly;
using namespace folly::test;
using namespace fizz::client;
using namespace fizz::extensions;
using namespace fizz::server;

namespace fizz {
namespace test {

struct ExpectedParameters {
  ProtocolVersion version{ProtocolVersion::tls_1_3};
  CipherSuite cipher{CipherSuite::TLS_AES_128_GCM_SHA256};
  folly::Optional<SignatureScheme> scheme{
      SignatureScheme::ecdsa_secp256r1_sha256};
  folly::Optional<NamedGroup> group{NamedGroup::x25519};
  PskType pskType{PskType::NotAttempted};
  folly::Optional<PskKeyExchangeMode> pskMode;
  folly::Optional<KeyExchangeType> clientKexType{KeyExchangeType::OneRtt};
  folly::Optional<KeyExchangeType> serverKexType{KeyExchangeType::OneRtt};
  folly::Optional<EarlyDataType> earlyDataType{EarlyDataType::NotAttempted};
  folly::Optional<std::string> alpn;
  std::shared_ptr<const Cert> clientCert;
  folly::Optional<CertificateCompressionAlgorithm> serverCertCompAlgo;
};

class HandshakeTest : public Test {
 public:
  void SetUp() override {
    CryptoUtils::init();

    clientContext_ = std::make_shared<FizzClientContext>();
    serverContext_ = std::make_shared<FizzServerContext>();

    auto pskCache = std::make_shared<BasicPskCache>();
    clientContext_->setPskCache(std::move(pskCache));

    auto certManager = std::make_unique<CertManager>();
    std::vector<std::shared_ptr<CertificateCompressor>> compressors = {
        std::make_shared<ZlibCertificateCompressor>(9)};
    std::vector<ssl::X509UniquePtr> rsaCerts;
    rsaCerts.emplace_back(getCert(kRSACertificate));
    certManager->addCert(
        std::make_shared<SelfCertImpl<KeyType::RSA>>(
            getPrivateKey(kRSAKey), std::move(rsaCerts), compressors),
        true);
    std::vector<ssl::X509UniquePtr> p256Certs;
    std::vector<ssl::X509UniquePtr> p384Certs;
    std::vector<ssl::X509UniquePtr> p521Certs;
    p256Certs.emplace_back(getCert(kP256Certificate));
    p384Certs.emplace_back(getCert(kP384Certificate));
    p521Certs.emplace_back(getCert(kP521Certificate));
    certManager->addCert(std::make_shared<SelfCertImpl<KeyType::P256>>(
        getPrivateKey(kP256Key), std::move(p256Certs), compressors));
    certManager->addCert(std::make_shared<SelfCertImpl<KeyType::P384>>(
        getPrivateKey(kP384Key), std::move(p384Certs), compressors));
    certManager->addCert(std::make_shared<SelfCertImpl<KeyType::P521>>(
        getPrivateKey(kP521Key), std::move(p521Certs), compressors));
    serverContext_->setCertManager(std::move(certManager));
    serverContext_->setEarlyDataSettings(
        true,
        {std::chrono::seconds(-60), std::chrono::seconds(60)},
        std::make_shared<AllowAllReplayReplayCache>());

    auto caCert = getCert(kClientAuthCACert);
    auto clientCert = getCert(kClientAuthClientCert);
    auto clientKey = getPrivateKey(kClientAuthClientKey);
    folly::ssl::X509StoreUniquePtr store(X509_STORE_new());
    ASSERT_EQ(X509_STORE_add_cert(store.get(), caCert.get()), 1);
    auto verifier = std::make_shared<const DefaultCertificateVerifier>(
        VerificationContext::Server, std::move(store));
    serverContext_->setClientCertVerifier(verifier);
    std::vector<folly::ssl::X509UniquePtr> certVec;
    certVec.emplace_back(std::move(clientCert));
    auto clientSelfCert = std::make_shared<SelfCertImpl<KeyType::RSA>>(
        std::move(clientKey), std::move(certVec));
    clientContext_->setClientCertificate(std::move(clientSelfCert));

    auto ticketCipher = std::make_shared<AES128TicketCipher>();
    auto ticketSeed = RandomGenerator<32>().generateRandom();
    ticketCipher->setTicketSecrets({{range(ticketSeed)}});
    ticketCipher->setTicketValidity(std::chrono::seconds(60));
    serverContext_->setTicketCipher(std::move(ticketCipher));

    cookieCipher_ = std::make_shared<AES128CookieCipher>();
    auto cookieSeed = RandomGenerator<32>().generateRandom();
    cookieCipher_->setCookieSecrets({{range(cookieSeed)}});
    cookieCipher_->setContext(serverContext_.get());
    serverContext_->setCookieCipher(cookieCipher_);

    ON_CALL(clientRead_, isBufferMovable_()).WillByDefault(Return(true));
    ON_CALL(serverRead_, isBufferMovable_()).WillByDefault(Return(true));

    resetTransports();
  }

  void resetTransports() {
    clientTransport_ = new LocalTransport();
    auto client = LocalTransport::UniquePtr(clientTransport_);
    serverTransport_ = new LocalTransport();
    auto server = LocalTransport::UniquePtr(serverTransport_);
    client->attachEventBase(&evb_);
    server->attachEventBase(&evb_);
    client->setPeer(server.get());
    server->setPeer(client.get());

    client_.reset(new AsyncFizzClient(
        std::move(client), clientContext_, clientExtensions_));
    server_.reset(new AsyncFizzServer(
        std::move(server), serverContext_, serverExtensions_));
  }

  void resetTransportsAndStartCookieHandshake() {
    clientTransport_ = new LocalTransport();
    auto client = LocalTransport::UniquePtr(clientTransport_);
    serverTransport_ = new LocalTransport();
    auto server = LocalTransport::UniquePtr(serverTransport_);
    client->attachEventBase(&evb_);
    server->attachEventBase(&evb_);
    client->setPeer(server.get());
    server->setPeer(client.get());

    client_.reset(new AsyncFizzClient(
        std::move(client), clientContext_, clientExtensions_));

    folly::test::MockReadCallback serverRawRead;
    ON_CALL(serverRawRead, isBufferMovable_()).WillByDefault(Return(true));

    EXPECT_CALL(serverRawRead, readBufferAvailable_(_))
        .WillOnce(Invoke([&](std::unique_ptr<IOBuf>& readBuf) {
          server->setReadCB(nullptr);
          auto tokenOrRetry = cookieCipher_->getTokenOrRetry(
              std::move(readBuf), IOBuf::copyBuffer("test"));
          auto retry =
              std::move(boost::get<StatelessHelloRetryRequest>(tokenOrRetry));
          server->writeChain(nullptr, std::move(retry.data));
        }));

    server->setReadCB(&serverRawRead);
    doClientHandshake();
    EXPECT_EQ(server->getReadCallback(), nullptr);

    server_.reset(new AsyncFizzServer(
        std::move(server), serverContext_, serverExtensions_));
  }

  void resetTransportsAndDoCookieHandshake() {
    resetTransportsAndStartCookieHandshake();
    doServerHandshake();
  }

  void doHandshake() {
    client_->connect(
        &clientCallback_, nullptr, folly::none, std::string("Fizz"));
    server_->accept(&serverCallback_);
    evb_.loop();
  }

  void doClientHandshake() {
    client_->connect(
        &clientCallback_, nullptr, folly::none, std::string("Fizz"));
    evb_.loop();
  }

  void doServerHandshake() {
    server_->accept(&serverCallback_);
    evb_.loop();
  }

  void expectClientSuccess() {
    EXPECT_CALL(clientCallback_, _fizzHandshakeSuccess())
        .WillOnce(Invoke([this]() {
          client_->setReadCB(&clientRead_);
          if (!client_->isReplaySafe()) {
            client_->setReplaySafetyCallback(&replayCallback_);
          }
        }));
    ON_CALL(clientCallback_, _fizzHandshakeError(_))
        .WillByDefault(Invoke([](folly::exception_wrapper ex) {
          FAIL() << "Client Error: " << ex.what().toStdString();
        }));
    ON_CALL(clientRead_, readErr_(_))
        .WillByDefault(Invoke([](const AsyncSocketException& ex) {
          FAIL() << "Client Read Error: " << ex.what();
        }));
  }

  void expectServerSuccess() {
    EXPECT_CALL(serverCallback_, _fizzHandshakeSuccess())
        .WillOnce(Invoke([this]() { server_->setReadCB(&serverRead_); }));
    ON_CALL(serverCallback_, _fizzHandshakeError(_))
        .WillByDefault(Invoke([](folly::exception_wrapper ex) {
          FAIL() << "Server Error: " << ex.what().toStdString();
        }));
    ON_CALL(serverRead_, readErr_(_))
        .WillByDefault(Invoke([](const AsyncSocketException& ex) {
          FAIL() << "Server Read Error: " << ex.what();
        }));
  }

  void expectSuccess() {
    expectClientSuccess();
    expectServerSuccess();
  }

  void expectError(const std::string& clientStr, const std::string& serverStr) {
    EXPECT_CALL(clientCallback_, _fizzHandshakeError(_))
        .WillOnce(Invoke([clientStr](folly::exception_wrapper ex) {
          EXPECT_THAT(ex.what().toStdString(), HasSubstr(clientStr));
        }));
    EXPECT_CALL(serverCallback_, _fizzHandshakeError(_))
        .WillOnce(Invoke([serverStr](folly::exception_wrapper ex) {
          EXPECT_THAT(ex.what().toStdString(), HasSubstr(serverStr));
        }));
  }

  void expectServerError(
      const std::string& clientError,
      const std::string& serverError) {
    EXPECT_CALL(clientCallback_, _fizzHandshakeSuccess());
    client_->setReadCB(&readCallback_);
    EXPECT_CALL(readCallback_, readErr_(_))
        .WillOnce(Invoke([clientError](const AsyncSocketException& ex) {
          EXPECT_THAT(std::string(ex.what()), HasSubstr(clientError));
        }));
    EXPECT_CALL(serverCallback_, _fizzHandshakeError(_))
        .WillOnce(Invoke([serverError](folly::exception_wrapper ex) {
          EXPECT_THAT(ex.what().toStdString(), HasSubstr(serverError));
        }));
  }

  void clientWrite(StringPiece write) {
    client_->writeChain(nullptr, IOBuf::copyBuffer(write));
  }

  void serverWrite(StringPiece write) {
    server_->writeChain(nullptr, IOBuf::copyBuffer(write));
  }

  void expectClientRead(StringPiece read) {
    EXPECT_CALL(clientRead_, readBufferAvailable_(BufMatches(read)));
  }

  void expectServerRead(StringPiece read) {
    EXPECT_CALL(serverRead_, readBufferAvailable_(BufMatches(read)));
  }

  void expectEarlyDataRejectError() {
    EXPECT_CALL(clientRead_, readErr_(_))
        .WillOnce(Invoke([](const AsyncSocketException& ex) {
          EXPECT_EQ(ex.getType(), AsyncSocketException::EARLY_DATA_REJECTED);
        }));
  }

  void expectReplaySafety() {
    EXPECT_CALL(replayCallback_, onReplaySafe_());
  }

  void sendAppData() {
    expectClientRead("serverdata");
    expectServerRead("clientdata");
    clientWrite("clientdata");
    serverWrite("serverdata");
  }

  static bool certsMatch(
      const std::shared_ptr<const Cert>& a,
      const std::shared_ptr<const Cert>& b) {
    if (!a || !b) {
      return a == b;
    } else {
      return a->getIdentity() == b->getIdentity();
    }
  }

  void verifyEarlyParameters() {
    EXPECT_EQ(
        client_->getState().earlyDataParams()->version, expected_.version);
    EXPECT_EQ(client_->getState().earlyDataParams()->cipher, expected_.cipher);
    EXPECT_EQ(client_->getState().earlyDataParams()->alpn, expected_.alpn);
    EXPECT_TRUE(certsMatch(
        client_->getState().earlyDataParams()->clientCert,
        expected_.clientCert));
  }

  void verifyParameters() {
    EXPECT_EQ(*client_->getState().version(), expected_.version);
    EXPECT_EQ(*client_->getState().cipher(), expected_.cipher);
    EXPECT_EQ(client_->getState().sigScheme(), expected_.scheme);
    EXPECT_EQ(client_->getState().group(), expected_.group);
    EXPECT_EQ(*server_->getState().pskType(), expected_.pskType);
    EXPECT_EQ(client_->getState().pskMode(), expected_.pskMode);
    EXPECT_EQ(client_->getState().keyExchangeType(), expected_.clientKexType);
    EXPECT_EQ(client_->getState().earlyDataType(), expected_.earlyDataType);
    EXPECT_EQ(client_->getState().alpn(), expected_.alpn);
    EXPECT_TRUE(
        certsMatch(client_->getState().clientCert(), expected_.clientCert));

    EXPECT_EQ(*server_->getState().version(), expected_.version);
    EXPECT_EQ(*server_->getState().cipher(), expected_.cipher);
    EXPECT_EQ(server_->getState().sigScheme(), expected_.scheme);
    EXPECT_EQ(server_->getState().group(), expected_.group);
    EXPECT_EQ(*server_->getState().pskType(), expected_.pskType);
    EXPECT_EQ(server_->getState().pskMode(), expected_.pskMode);
    EXPECT_EQ(server_->getState().keyExchangeType(), expected_.serverKexType);
    EXPECT_EQ(server_->getState().earlyDataType(), expected_.earlyDataType);
    EXPECT_EQ(server_->getState().alpn(), expected_.alpn);
    EXPECT_TRUE(
        certsMatch(server_->getState().clientCert(), expected_.clientCert));
    EXPECT_EQ(
        client_->getState().serverCertCompAlgo(), expected_.serverCertCompAlgo);
    EXPECT_EQ(
        server_->getState().serverCertCompAlgo(), expected_.serverCertCompAlgo);
  }

  void setupResume() {
    expectSuccess();
    doHandshake();
    verifyParameters();
    resetTransports();
    expected_.scheme = none;
    expected_.pskType = PskType::Resumption;
    expected_.pskMode = PskKeyExchangeMode::psk_dhe_ke;
  }

  void setupResumeWithHRR() {
    serverContext_->setSupportedGroups({NamedGroup::secp256r1});
    expected_.group = NamedGroup::secp256r1;
    expectSuccess();
    doHandshake();
    verifyParameters();
    // Explicitly set a different supported group to trigger another
    // negotiation, even if group is cached
    serverContext_->setSupportedGroups({NamedGroup::x25519});
    expected_.group = NamedGroup::x25519;
    resetTransports();
    expected_.scheme = none;
    expected_.pskType = PskType::Resumption;
    expected_.pskMode = PskKeyExchangeMode::psk_dhe_ke;
  }

 protected:
  EventBase evb_;
  std::shared_ptr<FizzClientContext> clientContext_;
  std::shared_ptr<FizzServerContext> serverContext_;
  AsyncFizzClient::UniquePtr client_;
  AsyncFizzServer::UniquePtr server_;

  std::shared_ptr<AES128CookieCipher> cookieCipher_;

  fizz::client::test::MockHandshakeCallback clientCallback_;
  fizz::server::test::MockHandshakeCallback serverCallback_;

  folly::test::MockReadCallback readCallback_;

  std::shared_ptr<fizz::ClientExtensions> clientExtensions_;
  std::shared_ptr<fizz::ServerExtensions> serverExtensions_;

  LocalTransport* clientTransport_;
  LocalTransport* serverTransport_;

  MockReadCallback clientRead_;
  MockReadCallback serverRead_;

  MockReplaySafetyCallback replayCallback_;

  ExpectedParameters expected_;
};

class SigSchemeTest : public HandshakeTest,
                      public ::testing::WithParamInterface<SignatureScheme> {};

TEST_F(HandshakeTest, BasicHandshake) {
  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, BasicHandshakeTrickle) {
  clientTransport_->setTrickle(true);
  serverTransport_->setTrickle(true);
  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, P256) {
  clientContext_->setSupportedGroups(
      {NamedGroup::x25519, NamedGroup::secp256r1});
  clientContext_->setDefaultShares({NamedGroup::x25519, NamedGroup::secp256r1});
  serverContext_->setSupportedGroups({NamedGroup::secp256r1});
  expected_.group = NamedGroup::secp256r1;

  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, P384) {
  clientContext_->setSupportedGroups(
      {NamedGroup::x25519, NamedGroup::secp384r1});
  clientContext_->setDefaultShares({NamedGroup::x25519, NamedGroup::secp384r1});
  serverContext_->setSupportedGroups({NamedGroup::secp384r1});
  expected_.group = NamedGroup::secp384r1;

  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, P521) {
  clientContext_->setSupportedGroups(
      {NamedGroup::x25519, NamedGroup::secp521r1});
  clientContext_->setDefaultShares({NamedGroup::x25519, NamedGroup::secp521r1});
  serverContext_->setSupportedGroups({NamedGroup::secp521r1});
  expected_.group = NamedGroup::secp521r1;

  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, GroupServerPref) {
  clientContext_->setSupportedGroups(
      {NamedGroup::secp256r1, NamedGroup::x25519});
  clientContext_->setDefaultShares({NamedGroup::secp256r1, NamedGroup::x25519});
  serverContext_->setSupportedGroups(
      {NamedGroup::x25519, NamedGroup::secp256r1});
  expected_.group = NamedGroup::x25519;

  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, GroupMismatch) {
  clientContext_->setSupportedGroups({NamedGroup::secp256r1});
  clientContext_->setDefaultShares({NamedGroup::secp256r1});
  serverContext_->setSupportedGroups({NamedGroup::x25519});

  expectError("alert: handshake_failure", "no group match");
  doHandshake();
}

TEST_F(HandshakeTest, SchemeServerPref) {
  clientContext_->setSupportedSigSchemes(
      {SignatureScheme::ecdsa_secp256r1_sha256,
       SignatureScheme::rsa_pss_sha256});
  serverContext_->setSupportedSigSchemes(
      {SignatureScheme::rsa_pss_sha256,
       SignatureScheme::ecdsa_secp256r1_sha256});
  expected_.scheme = SignatureScheme::rsa_pss_sha256;

  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, SchemeMismatch) {
  clientContext_->setSupportedSigSchemes(
      {SignatureScheme::ecdsa_secp256r1_sha256});
  serverContext_->setSupportedSigSchemes({SignatureScheme::rsa_pss_sha256});

  // The server will try using its RSA cert anyway, so it will be the client
  // that actually rejects that.
  expectError("unsupported sig scheme", "alert: illegal_parameter");
  doHandshake();
}

TEST_F(HandshakeTest, HRR) {
  clientContext_->setDefaultShares({});
  expected_.clientKexType = expected_.serverKexType =
      KeyExchangeType::HelloRetryRequest;

  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, PskDheKe) {
  setupResume();

  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, HrrPskDheKe) {
  clientContext_->setDefaultShares({});
  expected_.clientKexType = expected_.serverKexType =
      KeyExchangeType::HelloRetryRequest;
  setupResumeWithHRR();
  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, HrrPskDheKeWithCache) {
  clientContext_->setDefaultShares({});
  expected_.clientKexType = expected_.serverKexType =
      KeyExchangeType::HelloRetryRequest;
  setupResume();

  // OneRtt as the first round should have cached the group
  expected_.clientKexType = expected_.serverKexType = KeyExchangeType::OneRtt;
  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, HrrIncompatiblePsk) {
  expectSuccess();
  doHandshake();
  verifyParameters();
  resetTransports();

  serverContext_->setSupportedGroups({NamedGroup::secp256r1});
  serverContext_->setSupportedCiphers({{CipherSuite::TLS_AES_256_GCM_SHA384}});
  expected_.group = NamedGroup::secp256r1;
  expected_.cipher = CipherSuite::TLS_AES_256_GCM_SHA384;
  expected_.clientKexType = expected_.serverKexType =
      KeyExchangeType::HelloRetryRequest;

  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, PskKe) {
  serverContext_->setSupportedPskModes({PskKeyExchangeMode::psk_ke});
  setupResume();

  expected_.group = none;
  expected_.pskMode = PskKeyExchangeMode::psk_ke;
  expected_.clientKexType = expected_.serverKexType = KeyExchangeType::None;

  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

// This test is only run with 1.1.0 as it requires chacha to run (chacha and
// aes-gcm-128 are the only ciphers with a compatible hash algorithm).
#if FOLLY_OPENSSL_HAS_CHACHA
TEST_F(HandshakeTest, ResumeChangeCipher) {
  setupResume();
  clientContext_->setSupportedCiphers(
      {CipherSuite::TLS_AES_128_GCM_SHA256,
       CipherSuite::TLS_CHACHA20_POLY1305_SHA256});
  serverContext_->setSupportedCiphers(
      {{CipherSuite::TLS_CHACHA20_POLY1305_SHA256},
       {CipherSuite::TLS_AES_128_GCM_SHA256}});

  expected_.cipher = CipherSuite::TLS_CHACHA20_POLY1305_SHA256;

  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}
#endif // FOLLY_OPENSSL_HAS_CHACHA

TEST_F(HandshakeTest, TestEkmSame) {
  expectSuccess();
  doHandshake();
  auto clientEkm = client_->getEkm("EXPORTER-Some-Label", nullptr, 32);
  auto serverEkm = server_->getEkm("EXPORTER-Some-Label", nullptr, 32);
  EXPECT_TRUE(IOBufEqualTo()(clientEkm, serverEkm));
  EXPECT_THROW(
      client_->getEarlyEkm("EXPORTER-Some-Label", nullptr, 32), std::exception);
  EXPECT_THROW(
      server_->getEarlyEkm("EXPORTER-Some-Label", nullptr, 32), std::exception);
}

TEST_F(HandshakeTest, TestEarlyEkmSame) {
  clientContext_->setSendEarlyData(true);
  setupResume();

  expectSuccess();
  doHandshake();
  auto clientEkm = client_->getEarlyEkm("EXPORTER-Some-Label", nullptr, 32);
  auto serverEkm = server_->getEarlyEkm("EXPORTER-Some-Label", nullptr, 32);
  EXPECT_TRUE(IOBufEqualTo()(clientEkm, serverEkm));
}

TEST_F(HandshakeTest, TestExtensions) {
  auto context = std::make_shared<TokenBindingContext>();
  auto clientTokBind = std::make_shared<TokenBindingClientExtension>(context);
  auto serverTokBind = std::make_shared<TokenBindingServerExtension>(context);
  clientExtensions_ = clientTokBind;
  serverExtensions_ = serverTokBind;
  resetTransports();
  doHandshake();
  EXPECT_TRUE(clientTokBind->getNegotiatedKeyParam().hasValue());
  EXPECT_TRUE(clientTokBind->getVersion().hasValue());
  EXPECT_TRUE(serverTokBind->getNegotiatedKeyParam().hasValue());
  EXPECT_EQ(
      *clientTokBind->getNegotiatedKeyParam(),
      TokenBindingKeyParameters::ecdsap256);
  EXPECT_EQ(
      *clientTokBind->getVersion(),
      TokenBindingProtocolVersion::token_binding_0_14);
  EXPECT_EQ(
      *serverTokBind->getNegotiatedKeyParam(),
      TokenBindingKeyParameters::ecdsap256);
}

TEST_F(HandshakeTest, BasicCertRequest) {
  expectSuccess();
  serverContext_->setClientAuthMode(ClientAuthMode::Required);
  expected_.clientCert = std::make_shared<PeerCertImpl<KeyType::RSA>>(
      getCert(kClientAuthClientCert));
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_P(SigSchemeTest, Schemes) {
  SignatureScheme scheme = GetParam();
  clientContext_->setSupportedSigSchemes({scheme});
  serverContext_->setSupportedSigSchemes({scheme});
  expected_.scheme = scheme;

  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, CertRequestPskPreservesIdentity) {
  serverContext_->setClientAuthMode(ClientAuthMode::Required);
  expected_.clientCert = std::make_shared<PeerCertImpl<KeyType::RSA>>(
      getCert(kClientAuthClientCert));
  setupResume();

  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, CertRequestNoCert) {
  serverContext_->setClientAuthMode(ClientAuthMode::Required);
  clientContext_->setClientCertificate(nullptr);
  expectServerError(
      "alert: certificate_required", "certificate requested but none received");
  doHandshake();
}

TEST_F(HandshakeTest, CertRequestPermitNoCert) {
  serverContext_->setClientAuthMode(ClientAuthMode::Optional);
  clientContext_->setClientCertificate(nullptr);
  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, CertRequestBadCert) {
  serverContext_->setClientAuthMode(ClientAuthMode::Required);
  auto badCert = createCert("foo", false, nullptr);
  std::vector<folly::ssl::X509UniquePtr> certVec;
  certVec.emplace_back(std::move(badCert.cert));
  clientContext_->setClientCertificate(
      std::make_shared<SelfCertImpl<KeyType::P256>>(
          std::move(badCert.key), std::move(certVec)));
  expectServerError("alert: bad_certificate", "client certificate failure");
  doHandshake();
}

TEST_F(HandshakeTest, BasicCertCompression) {
  expectSuccess();
  auto decompressor = std::make_shared<ZlibCertificateDecompressor>();
  auto decompressionMgr = std::make_shared<CertDecompressionManager>();
  decompressionMgr->setDecompressors(
      {std::static_pointer_cast<CertificateDecompressor>(decompressor)});
  clientContext_->setCertDecompressionManager(decompressionMgr);
  serverContext_->setSupportedCompressionAlgorithms(
      {CertificateCompressionAlgorithm::zlib});
  expected_.serverCertCompAlgo = CertificateCompressionAlgorithm::zlib;
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, EarlyDataAccepted) {
  clientContext_->setSendEarlyData(true);
  setupResume();

  expected_.pskType = PskType::Resumption;
  expected_.earlyDataType = EarlyDataType::Accepted;

  expectClientSuccess();
  doClientHandshake();
  verifyEarlyParameters();
  clientWrite("early");

  expectReplaySafety();
  expectServerSuccess();
  expectServerRead("early");
  doServerHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, EarlyDataRejected) {
  clientContext_->setSendEarlyData(true);
  setupResume();

  serverContext_->setEarlyDataSettings(false, {}, nullptr);
  expected_.pskType = PskType::Resumption;
  expected_.earlyDataType = EarlyDataType::Rejected;

  expectClientSuccess();
  doClientHandshake();
  verifyEarlyParameters();
  clientWrite("early");

  expectEarlyDataRejectError();
  expectServerSuccess();
  doServerHandshake();
  verifyParameters();
}

TEST_F(HandshakeTest, EarlyDataRejectedHrr) {
  clientContext_->setSendEarlyData(true);
  setupResume();

  serverContext_->setSupportedGroups({NamedGroup::secp256r1});
  expected_.pskType = PskType::Resumption;
  expected_.earlyDataType = EarlyDataType::Rejected;
  expected_.clientKexType = expected_.serverKexType =
      KeyExchangeType::HelloRetryRequest;
  expected_.group = NamedGroup::secp256r1;

  expectClientSuccess();
  doClientHandshake();
  verifyEarlyParameters();
  clientWrite("early");

  expectEarlyDataRejectError();
  expectServerSuccess();
  doServerHandshake();
  verifyParameters();
}

TEST_F(HandshakeTest, EarlyDataRejectedResend) {
  clientContext_->setSendEarlyData(true);
  setupResume();

  serverContext_->setEarlyDataSettings(false, {}, nullptr);
  client_->setEarlyDataRejectionPolicy(
      EarlyDataRejectionPolicy::AutomaticResend);
  expected_.pskType = PskType::Resumption;
  expected_.earlyDataType = EarlyDataType::Rejected;

  expectClientSuccess();
  doClientHandshake();
  verifyEarlyParameters();
  clientWrite("early");

  expectReplaySafety();
  expectServerRead("early");
  expectServerSuccess();
  doServerHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, EarlyDataRejectedDontResend) {
  clientContext_->setSendEarlyData(true);
  clientContext_->setSupportedAlpns({"h2"});
  serverContext_->setSupportedAlpns({"h2"});
  expected_.alpn = "h2";
  setupResume();

  serverContext_->setSupportedAlpns({});
  client_->setEarlyDataRejectionPolicy(
      EarlyDataRejectionPolicy::AutomaticResend);

  expectClientSuccess();
  doClientHandshake();
  verifyEarlyParameters();
  clientWrite("early");

  expected_.earlyDataType = EarlyDataType::Rejected;
  expected_.alpn = none;

  expectEarlyDataRejectError();
  expectServerSuccess();
  doServerHandshake();
  verifyParameters();

  expected_.pskType = PskType::NotAttempted;
  expected_.pskMode = none;
  expected_.scheme = SignatureScheme::ecdsa_secp256r1_sha256;
  expected_.earlyDataType = EarlyDataType::NotAttempted;

  resetTransports();
  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, EarlyDataTrickleSendAccepted) {
  clientContext_->setSendEarlyData(true);
  setupResume();

  clientTransport_->setTrickle(true, [this]() { clientWrite("e"); });
  expected_.pskType = PskType::Resumption;
  expected_.earlyDataType = EarlyDataType::Accepted;

  expectClientSuccess();
  doClientHandshake();
  verifyEarlyParameters();

  expectReplaySafety();
  expectServerSuccess();
  doServerHandshake();
  verifyParameters();
}

TEST_F(HandshakeTest, EarlyDataTrickleSendRejected) {
  clientContext_->setSendEarlyData(true);
  setupResume();

  clientTransport_->setTrickle(true, [this]() { clientWrite("e"); });
  serverContext_->setClientAuthMode(ClientAuthMode::Required);
  serverContext_->setTicketCipher(nullptr);

  expectClientSuccess();
  doClientHandshake();
  verifyEarlyParameters();

  expected_.pskType = PskType::Rejected;
  expected_.pskMode = none;
  expected_.earlyDataType = EarlyDataType::Rejected;
  expected_.scheme = SignatureScheme::ecdsa_secp256r1_sha256;
  expected_.clientCert = std::make_shared<PeerCertImpl<KeyType::RSA>>(
      getCert(kClientAuthClientCert));

  expectEarlyDataRejectError();
  expectServerSuccess();
  doServerHandshake();
  verifyParameters();
}

TEST_F(HandshakeTest, EarlyDataAcceptedOmitEarlyRecord) {
  clientContext_->setSendEarlyData(true);
  clientContext_->setOmitEarlyRecordLayer(true);
  serverContext_->setOmitEarlyRecordLayer(true);
  setupResume();

  expected_.pskType = PskType::Resumption;
  expected_.earlyDataType = EarlyDataType::Accepted;

  expectClientSuccess();
  doClientHandshake();
  verifyEarlyParameters();

  expectReplaySafety();
  expectServerSuccess();
  doServerHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, Compat) {
  clientContext_->setCompatibilityMode(true);
  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, TestCompatHRR) {
  clientContext_->setCompatibilityMode(true);
  clientContext_->setDefaultShares({});
  expected_.clientKexType = expected_.serverKexType =
      KeyExchangeType::HelloRetryRequest;

  expectSuccess();
  doHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, TestCompatEarly) {
  clientContext_->setCompatibilityMode(true);
  clientContext_->setSendEarlyData(true);
  setupResume();

  expected_.pskType = PskType::Resumption;
  expected_.earlyDataType = EarlyDataType::Accepted;

  expectClientSuccess();
  doClientHandshake();
  verifyEarlyParameters();

  expectReplaySafety();
  expectServerSuccess();
  doServerHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, TestCompatEarlyRejected) {
  clientContext_->setCompatibilityMode(true);
  clientContext_->setSendEarlyData(true);
  setupResume();

  serverContext_->setEarlyDataSettings(false, {}, nullptr);
  expected_.pskType = PskType::Resumption;
  expected_.earlyDataType = EarlyDataType::Rejected;

  expectClientSuccess();
  doClientHandshake();
  verifyEarlyParameters();
  clientWrite("early");

  expectEarlyDataRejectError();
  expectServerSuccess();
  doServerHandshake();
  verifyParameters();
}

TEST_F(HandshakeTest, TestCompatEarlyRejectedHRR) {
  clientContext_->setCompatibilityMode(true);
  clientContext_->setSendEarlyData(true);
  setupResume();

  serverContext_->setSupportedGroups({NamedGroup::secp256r1});
  expected_.pskType = PskType::Resumption;
  expected_.earlyDataType = EarlyDataType::Rejected;
  expected_.clientKexType = expected_.serverKexType =
      KeyExchangeType::HelloRetryRequest;
  expected_.group = NamedGroup::secp256r1;

  expectClientSuccess();
  doClientHandshake();
  verifyEarlyParameters();
  clientWrite("early");

  expectEarlyDataRejectError();
  expectServerSuccess();
  doServerHandshake();
  verifyParameters();
}

TEST_F(HandshakeTest, TestCookie) {
  expected_.clientKexType = KeyExchangeType::HelloRetryRequest;

  expectSuccess();
  resetTransportsAndDoCookieHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, TestCookieGroupNegotiate) {
  clientContext_->setDefaultShares({});
  expected_.clientKexType = KeyExchangeType::HelloRetryRequest;

  expectSuccess();
  resetTransportsAndDoCookieHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, TestCookieResume) {
  setupResume();

  expected_.clientKexType = KeyExchangeType::HelloRetryRequest;

  expectSuccess();
  resetTransportsAndDoCookieHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, TestCookieIncompatiblePsk) {
  expectSuccess();
  doHandshake();
  verifyParameters();

  serverContext_->setSupportedCiphers({{CipherSuite::TLS_AES_256_GCM_SHA384}});
  expected_.cipher = CipherSuite::TLS_AES_256_GCM_SHA384;
  expected_.clientKexType = KeyExchangeType::HelloRetryRequest;

  expectSuccess();
  resetTransportsAndDoCookieHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, TestCookiePskKe) {
  serverContext_->setSupportedPskModes({PskKeyExchangeMode::psk_ke});
  setupResume();

  expected_.group = none;
  expected_.pskMode = PskKeyExchangeMode::psk_ke;
  expected_.clientKexType = KeyExchangeType::None;
  expected_.serverKexType = KeyExchangeType::None;

  expectSuccess();
  resetTransportsAndDoCookieHandshake();
  verifyParameters();
  sendAppData();
}

TEST_F(HandshakeTest, TestBadCookie) {
  expectError("decrypt_error", "could not decrypt cookie");
  resetTransportsAndStartCookieHandshake();

  auto cookieSeed = RandomGenerator<32>().generateRandom();
  cookieCipher_->setCookieSecrets({{range(cookieSeed)}});

  doServerHandshake();
}
INSTANTIATE_TEST_CASE_P(
    SignatureSchemes,
    SigSchemeTest,
    ::testing::Values(
        SignatureScheme::rsa_pss_sha256,
        SignatureScheme::ecdsa_secp256r1_sha256,
        SignatureScheme::ecdsa_secp384r1_sha384,
        SignatureScheme::ecdsa_secp521r1_sha512));
} // namespace test
} // namespace fizz
