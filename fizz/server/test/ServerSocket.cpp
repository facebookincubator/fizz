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

class TestCallbackFactory
    : public fizz::server::test::FizzTestServer::CallbackFactory {
 public:
  TestCallbackFactory(EventBase* evb, std::shared_ptr<SSLContext> sslContext)
      : evb_(evb), sslContext_(sslContext) {}

  AsyncFizzServer::HandshakeCallback* getCallback(
      std::shared_ptr<AsyncFizzServer> server) override {
    return new Callback(evb_, sslContext_, std::move(server));
  }

 private:
  class Callback : public AsyncFizzServer::HandshakeCallback,
                   public AsyncSSLSocket::HandshakeCB,
                   public AsyncTransportWrapper::ReadCallback {
   public:
    Callback(
        EventBase* evb,
        std::shared_ptr<SSLContext> sslContext,
        std::shared_ptr<AsyncFizzServer> server)
        : evb_(evb), sslContext_(sslContext), fizzServer_(server) {}

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
      CHECK(fizzServer_);
      LOG(INFO) << "Fallback attempt";
      auto fd = fizzServer_->getUnderlyingTransport<AsyncSocket>()->detachFd();
      fizzServer_.reset();
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
      LOG(FATAL) << "getReadBuffer not implemented";
    }

    void readDataAvailable(size_t) noexcept override {
      LOG(FATAL) << "readDataAvailable not implemented";
    }

    bool isBufferMovable() noexcept override {
      return true;
    }

    void readBufferAvailable(std::unique_ptr<IOBuf> buf) noexcept override {
      VLOG(1) << "Data received.";
      VLOG(1) << "Hex:" << std::endl << hexlify(buf->coalesce());
      VLOG(1) << "Raw:" << std::endl << StringPiece(buf->coalesce());

      auto clientCert = fizzServer_->getState().clientCert();
      auto serverCert = fizzServer_->getState().serverCert();
      auto alpn = fizzServer_->getState().alpn();
      auto negotiatedGroup = fizzServer_->getState().group();
      auto negotiatedSigScheme = fizzServer_->getState().sigScheme();
      auto pskMode = fizzServer_->getState().pskMode();

      // clang-format off
      auto response = folly::to<std::string>(
          "Fizz Test Server\n",
          "----------------\n",
          "Server Identity: ", serverCert ? serverCert->getIdentity() : "(none)", "\n",
          "Client Identity: ", clientCert ? clientCert->getIdentity() : "(none)", "\n",
          "ALPN: ", alpn ? *alpn : "(none)", "\n",
          "Early Data: ", toString(*fizzServer_->getState().earlyDataType()), "\n",
          "TLS Version: ", toString(*fizzServer_->getState().version()), "\n",
          "Cipher Suite: ", toString(*fizzServer_->getState().cipher()), "\n",
          "Named Group: ", negotiatedGroup ? toString(*negotiatedGroup) : "(none)", "\n",
          "Signature Scheme: ", negotiatedSigScheme ? toString(*negotiatedSigScheme) : "(none)", "\n"
          "PSK Type: ", toString(*fizzServer_->getState().pskType()), "\n"
          "PSK Mode: ", pskMode ? toString(*pskMode) : "(none)", "\n",
          "Key Exchange Type: ", toString(*fizzServer_->getState().keyExchangeType()), "\n");
      // clang-format on

      std::array<char, 4> getPrefix = {'G', 'E', 'T', ' '};
      auto range = buf->coalesce();
      if (range.size() > 4 && memcmp(range.data(), getPrefix.data(), 4) == 0) {
        // clang-format off
        auto rawResponse = folly::to<std::string>(
            "HTTP/1.1 200 OK\n",
            "Content-Length: ", response.size(), "\n",
            "Content-Type: text/plain\n",
            "Connection: Close\n\n",
            response);
        // clang-format on

        fizzServer_->writeChain(nullptr, IOBuf::copyBuffer(rawResponse));
      }
    }

    void readEOF() noexcept override {
      LOG(INFO) << "Read EOF";
      delete this;
    }

    void readErr(const AsyncSocketException& ex) noexcept override {
      LOG(ERROR) << "Read error: " << ex.what();
      delete this;
    }

   private:
    EventBase* evb_;
    std::shared_ptr<SSLContext> sslContext_;
    AsyncSSLSocket::UniquePtr sslSocket_;
    std::shared_ptr<AsyncFizzServer> fizzServer_;
  };
  EventBase* evb_;
  std::shared_ptr<SSLContext> sslContext_;
};

int main(int argc, char** argv) {
  // Works around some platforms where it doesn't log by default.
  FLAGS_logtostderr = true;
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
  TestCallbackFactory factory(&evb, sslContext);
  fizz::server::test::FizzTestServer serv(evb, &factory, FLAGS_port);

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

  serv.setResumption(true);
  if (FLAGS_clientauth && !FLAGS_cabundle.empty()) {
    serv.enableClientAuthWithChain(FLAGS_cabundle);
  }
  serv.setAcceptEarlyData(FLAGS_early);

  // Handle advanced settings
  auto serverContext = serv.getFizzContext();
  serverContext->setSupportedAlpns({"http/1.1"});
  serverContext->setSupportedVersions({ProtocolVersion::tls_1_3,
                                       ProtocolVersion::tls_1_3_26,
                                       ProtocolVersion::tls_1_3_23});
  serverContext->setVersionFallbackEnabled(FLAGS_fallback);

  SocketAddress address = serv.getAddress();
  LOG(INFO) << "Serving on " << address;
  evb.loopForever();
}
