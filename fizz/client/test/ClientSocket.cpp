/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/client/AsyncFizzClient.h>
#include <fizz/crypto/Utils.h>
#include <folly/ssl/Init.h>

DEFINE_string(host, "localhost", "host to connect to");
DEFINE_int32(port, 443, "port to connect to");
DEFINE_string(sni, "", "server_name to send (will send host if unspecified)");
DEFINE_string(cert, "", "client certificate to use");
DEFINE_string(key, "", "client private key to use");
DEFINE_bool(
    resume,
    false,
    "make two connections using the session ticket from the first connection "
    "for the second one");
DEFINE_bool(early, false, "send early data");
DEFINE_bool(verify, false, "enable verification of server certificate chain");

using namespace fizz;
using namespace fizz::client;
using namespace folly;

class Connection : public AsyncSocket::ConnectCallback,
                   public AsyncFizzClient::HandshakeCallback,
                   public AsyncTransportWrapper::ReadCallback,
                   public AsyncTransport::ReplaySafetyCallback {
 public:
  Connection(
      EventBase* evb,
      std::shared_ptr<FizzClientContext> clientContext,
      Optional<std::string> sni,
      std::shared_ptr<const CertificateVerifier> verifier)
      : evb_(evb),
        clientContext_(clientContext),
        sni_(sni),
        verifier_(std::move(verifier)) {}

  void connect(const SocketAddress& addr) {
    sock_ = AsyncSocket::UniquePtr(new AsyncSocket(evb_));
    sock_->connect(this, addr);
  }

  void close() {
    if (sock_) {
      sock_->close();
    } else if (transport_) {
      transport_->close();
    }
  }

  void connectErr(const AsyncSocketException& ex) noexcept override {
    LOG(ERROR) << "Connect error: " << ex.what();
  }

  void connectSuccess() noexcept override {
    LOG(INFO) << "Connected";
    transport_ = AsyncFizzClient::UniquePtr(
        new AsyncFizzClient(std::move(sock_), clientContext_));
    transport_->connect(this, verifier_, sni_, sni_);
  }

  void fizzHandshakeSuccess(AsyncFizzClient* /*client*/) noexcept override {
    if (transport_->isReplaySafe()) {
      printHandshakeSuccess();
    } else {
      LOG(INFO) << "Early handshake success";
      transport_->setReplaySafetyCallback(this);
    }
    transport_->setReadCB(this);
    transport_->writeChain(
        nullptr, IOBuf::copyBuffer("GET / HTTP/1.1\r\n\r\n"));
  }

  void fizzHandshakeError(
      AsyncFizzClient* /*client*/,
      folly::exception_wrapper ex) noexcept override {
    LOG(ERROR) << "Handshake error: " << ex.what();
  }

  void getReadBuffer(void** /* bufReturn */, size_t* /* lenReturn */) override {
    CHECK(false) << __func__ << " should not be invoked";
  }

  void readDataAvailable(size_t /* len */) noexcept override {
    CHECK(false) << __func__ << " should not be invoked";
  }

  bool isBufferMovable() noexcept override {
    return true;
  }

  void readBufferAvailable(std::unique_ptr<IOBuf> buf) noexcept override {
    LOG(INFO) << "Data received: " << StringPiece(buf->coalesce());
  }

  void readEOF() noexcept override {
    LOG(INFO) << "Read EOF";
  }

  void readErr(const AsyncSocketException& ex) noexcept override {
    LOG(ERROR) << "Read error: " << ex.what();
  }

  void onReplaySafe() override {
    printHandshakeSuccess();
  }

 private:
  void printHandshakeSuccess() {
    auto serverCert = transport_->getState().serverCert();
    LOG(INFO) << "Handshake success"
              << ", psk: " << toString(*transport_->getState().pskType())
              << ", early: "
              << toString(*transport_->getState().earlyDataType())
              << ", server identity: "
              << (serverCert ? serverCert->getIdentity() : "(none)");
  }

  EventBase* evb_;
  std::shared_ptr<FizzClientContext> clientContext_;
  Optional<std::string> sni_;
  std::shared_ptr<const CertificateVerifier> verifier_;
  AsyncSocket::UniquePtr sock_;
  AsyncFizzClient::UniquePtr transport_;
};

// PskCache class used only when we want to use a psk to resume a connection
// Callback passed in should initiate a new connection - which would then use
// the psk in the cache.
class ResumptionPskCache : public BasicPskCache {
 public:
  ResumptionPskCache(folly::EventBase* evb, folly::Function<void()> callback)
      : evb_(evb), callback_(std::move(callback)) {}

  void putPsk(const std::string& identity, CachedPsk psk) override {
    BasicPskCache::putPsk(identity, std::move(psk));
    if (callback_) {
      evb_->runInLoop(std::move(callback_));
      callback_ = nullptr;
    }
  }

 private:
  folly::EventBase* evb_;
  folly::Function<void()> callback_;
};

int main(int argc, char** argv) {
  // Works around some platforms where it doesn't log by default.
  FLAGS_logtostderr = true;
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  CryptoUtils::init();

  auto clientContext = std::make_shared<FizzClientContext>();
  clientContext->setSupportedAlpns({"http/1.1"});
  clientContext->setSupportedVersions({ProtocolVersion::tls_1_3,
                                       ProtocolVersion::tls_1_3_26,
                                       ProtocolVersion::tls_1_3_23});
  clientContext->setSendEarlyData(FLAGS_early);

  SocketAddress addr(FLAGS_host, FLAGS_port, true);

  EventBase evb;
  auto sni = FLAGS_sni.empty() ? FLAGS_host : FLAGS_sni;

  std::shared_ptr<const CertificateVerifier> verifier;
  if (FLAGS_verify) {
    verifier = std::make_shared<const DefaultCertificateVerifier>(
        VerificationContext::Client);
  }
  Connection conn(&evb, clientContext, sni, verifier);
  Connection resumptionConn(&evb, clientContext, sni, verifier);

  if (FLAGS_resume) {
    auto pskCache = std::make_shared<ResumptionPskCache>(
        &evb, [&conn, &resumptionConn, addr]() {
          conn.close();
          resumptionConn.connect(addr);
        });
    clientContext->setPskCache(pskCache);
  }

  CHECK_EQ(FLAGS_cert.empty(), FLAGS_key.empty())
      << "-cert and -key are both required when specified";

  if (!FLAGS_cert.empty()) {
    folly::ssl::BioUniquePtr b(BIO_new(BIO_s_file()));
    CHECK(b);
    BIO_read_filename(b.get(), FLAGS_cert.c_str());
    std::vector<folly::ssl::X509UniquePtr> certs;
    while (true) {
      folly::ssl::X509UniquePtr x509(
          PEM_read_bio_X509(b.get(), nullptr, nullptr, nullptr));
      if (!x509) {
        break;
      }
      certs.push_back(std::move(x509));
    }
    CHECK(!certs.empty()) << "Could not read any certs";

    b.reset(BIO_new(BIO_s_file()));
    CHECK(b);
    BIO_read_filename(b.get(), FLAGS_key.c_str());
    folly::ssl::EvpPkeyUniquePtr key(
        PEM_read_bio_PrivateKey(b.get(), nullptr, nullptr, nullptr));
    CHECK(key) << "Could not read key";

    folly::ssl::EvpPkeyUniquePtr pubKey(X509_get_pubkey(certs.front().get()));
    CHECK(pubKey);

    std::shared_ptr<SelfCert> cert;
    if (EVP_PKEY_id(pubKey.get()) == EVP_PKEY_RSA) {
      cert = std::make_shared<SelfCertImpl<KeyType::RSA>>(
          std::move(key), std::move(certs));
    } else {
      cert = std::make_shared<SelfCertImpl<KeyType::P256>>(
          std::move(key), std::move(certs));
    }
    clientContext->setClientCertificate(std::move(cert));
  }

  conn.connect(addr);
  evb.loopForever();
}
