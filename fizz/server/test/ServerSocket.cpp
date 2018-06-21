/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/server/test/Utils.h>
#include <folly/String.h>
#include <folly/io/async/AsyncSSLSocket.h>
#include <folly/io/async/AsyncServerSocket.h>
#include <folly/io/async/SSLContext.h>
#include <folly/ssl/Init.h>

DEFINE_int32(port, 8443, "port to listen on");
DEFINE_string(cert, "", "certificate to use");
DEFINE_string(key, "", "certificate key to use");
DEFINE_string(cabundle, "", "CA certificate bundle to use for client auth");
DEFINE_bool(clientauth, false, "require client authentication");
DEFINE_bool(fallback, false, "enabled AsyncSSLSocket fallback");
DEFINE_bool(early, false, "accept early data");

using namespace fizz;
using namespace fizz::server;
using namespace folly;
using namespace folly::ssl;

class Callback : public AsyncFizzServer::HandshakeCallback,
                 public AsyncSSLSocket::HandshakeCB,
                 public AsyncTransportWrapper::ReadCallback {
 public:
  Callback(EventBase* evb, std::shared_ptr<SSLContext> sslContext)
      : evb_(evb), sslContext_(sslContext) {}

  void fizzHandshakeSuccess(AsyncFizzServer* server) noexcept override {
    auto clientCert = server->getState().clientCert();
    LOG(INFO) << "Handshake success"
              << ", psk: " << toString(*server->getState().pskType())
              << ", client identity: "
              << (clientCert ? clientCert->getIdentity() : "(none)")
              << ", early data: "
              << toString(*server->getState().earlyDataType());
    server->setReadCB(this);
  }

  void fizzHandshakeError(
      AsyncFizzServer* /*server*/,
      folly::exception_wrapper ex) noexcept override {
    LOG(ERROR) << "Handshake error: " << ex.what();
  }

  void fizzHandshakeAttemptFallback(
      std::unique_ptr<folly::IOBuf> clientHello) override {
    CHECK(serverRef_);
    LOG(INFO) << "Fallback attempt";
    auto fd = serverRef_->getTransport()
                  ->getUnderlyingTransport<AsyncSocket>()
                  ->detachFd();
    serverRef_->getTransport().reset();
    sslSocket_ =
        AsyncSSLSocket::UniquePtr(new AsyncSSLSocket(sslContext_, evb_, fd));
    sslSocket_->setPreReceivedData(std::move(clientHello));
    sslSocket_->sslAccept(this);
  }

  void handshakeSuc(folly::AsyncSSLSocket* /*sock*/) noexcept override {
    LOG(INFO) << "Fallback SSL Handshake success";
  }

  void handshakeErr(
      folly::AsyncSSLSocket* /*sock*/,
      const folly::AsyncSocketException& ex) noexcept override {
    LOG(ERROR) << "Fallback SSL Handshake error: " << ex.what();
  }

  void getReadBuffer(void**, size_t*) override {
    throw std::runtime_error("getReadBuffer not implemented");
  }

  void readDataAvailable(size_t) noexcept override {
    throw std::runtime_error("readDataAvailable not implemented");
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

  void setServerRef(fizz::server::test::FizzTestServer* ref) {
    serverRef_ = ref;
  }

 private:
  EventBase* evb_;
  std::shared_ptr<SSLContext> sslContext_;
  AsyncSSLSocket::UniquePtr sslSocket_;
  fizz::server::test::FizzTestServer* serverRef_;
};

int main(int argc, char** argv) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  folly::ssl::init();

  if (FLAGS_cert.empty() ^ FLAGS_key.empty()) {
    LOG(ERROR) << "Both -cert and -key required when either is provided.";
    return 1;
  }

  // Create SSL context for fallback if necessary
  std::shared_ptr<SSLContext> sslContext;
  if (FLAGS_fallback) {
    sslContext = std::make_shared<SSLContext>();
    sslContext->loadCertificate(FLAGS_cert.c_str(), "PEM");
    sslContext->loadPrivateKey(FLAGS_key.c_str(), "PEM");
    auto ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SSL_CTX_set_tmp_ecdh(sslContext->getSSLCtx(), ecdh);
    EC_KEY_free(ecdh);
  }

  EventBase evb;
  Callback cb(&evb, sslContext);
  fizz::server::test::FizzTestServer serv(evb, &cb, FLAGS_port);

  if (!FLAGS_cert.empty()) {
    std::string certBuf, keyBuf;

    if (!folly::readFile(FLAGS_cert.c_str(), certBuf)) {
      LOG(ERROR) << "Failed to read cert.";
      return 1;
    }

    if (!folly::readFile(FLAGS_key.c_str(), keyBuf)) {
      LOG(ERROR) << "Failed to read key.";
      return 1;
    }

    auto cert = CertUtils::makeSelfCert(certBuf, keyBuf);
    serv.setCertificate(std::move(cert));
  } else {
    LOG(INFO) << "No certificate/key specified, using a self-signed cert.";
  }

  cb.setServerRef(&serv);
  serv.setResumption(true);
  if (FLAGS_clientauth && !FLAGS_cabundle.empty()) {
    serv.enableClientAuthWithChain(FLAGS_cabundle);
  }
  serv.setAcceptEarlyData(FLAGS_early);

  // Handle advanced settings
  auto serverContext = serv.getFizzContext();
  serverContext->setSupportedAlpns({"h2", "http/1.1"});
  serverContext->setSupportedVersions(
      {ProtocolVersion::tls_1_3_26, ProtocolVersion::tls_1_3_23});
  serverContext->setVersionFallbackEnabled(FLAGS_fallback);

  SocketAddress address = serv.getAddress();
  LOG(INFO) << "Serving on " << address;
  evb.loopForever();
}
