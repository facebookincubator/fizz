/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/crypto/aead/AESGCM128.h>
#include <fizz/crypto/aead/OpenSSLEVPCipher.h>
#include <fizz/protocol/DefaultCertificateVerifier.h>
#include <fizz/protocol/ZlibCertificateCompressor.h>
#include <fizz/protocol/test/Utilities.h>
#include <fizz/server/AsyncFizzServer.h>
#include <fizz/server/SlidingBloomReplayCache.h>
#include <fizz/server/TicketTypes.h>
#include <fizz/tool/FizzCommandCommon.h>
#include <fizz/util/Parse.h>

#include <folly/io/async/AsyncSSLSocket.h>
#include <folly/io/async/AsyncServerSocket.h>

#include <string>
#include <vector>

using namespace fizz::server;
using namespace folly;

namespace fizz {
namespace tool {
namespace {

void printUsage() {
  // clang-format off
  std::cerr
    << "Usage: s_server args\n"
    << "\n"
    << "Supported arguments:\n"
    << " -accept port             (set port to accept connections on. Default: 8443)\n"
    << " -ciphers c1,...          (comma-separated custom list of ciphers to use in order of preference)\n"
    << " -cert cert               (PEM format server certificate. Default: none, generates a self-signed cert)\n"
    << " -key key                 (PEM format private key for server certificate. Default: none)\n"
    << " -pass password           (private key password. Default: none)\n"
    << " -requestcert             (request an optional client certificate from clients. Default: false)\n"
    << " -requirecert             (require a client certificate from clients. Default: false)\n"
    << " -capaths d1:...          (colon-separated paths to directories of CA certs used for verification)\n"
    << " -cafile file             (path to bundle of CA certs used for verification)\n"
    << " -early                   (enables sending early data during resumption. Default: false)\n"
    << " -alpn alpn1,.. .         (comma-separated list of ALPNs to support. Default: none)\n"
    << " -certcompression a1,...  (enables certificate compression support for given algorithms. Default: None)\n"
    << " -fallback                (enables falling back to OpenSSL for pre-1.3 connections. Default: false)\n"
    << " -loop                    (don't exit after client disconnect. Default: false)\n"
    << " -quiet                   (hide informational logging. Default: false)\n";
  // clang-format on
}

class FizzServerAcceptor : AsyncServerSocket::AcceptCallback {
 public:
  explicit FizzServerAcceptor(
      uint16_t port,
      std::shared_ptr<FizzServerContext> serverCtx,
      bool loop,
      EventBase* evb,
      std::shared_ptr<SSLContext> sslCtx);
  void connectionAccepted(
      int fd,
      const SocketAddress& clientAddr) noexcept override;

  void acceptError(const std::exception& ex) noexcept override;
  void done();

 private:
  bool loop_{false};
  EventBase* evb_{nullptr};
  std::shared_ptr<FizzServerContext> ctx_;
  std::shared_ptr<SSLContext> sslCtx_;
  AsyncServerSocket::UniquePtr socket_;
  std::unique_ptr<AsyncFizzServer::HandshakeCallback> cb_;
  std::unique_ptr<TerminalInputHandler> inputHandler_;
};

class FizzExampleServer : public AsyncFizzServer::HandshakeCallback,
                          public AsyncSSLSocket::HandshakeCB,
                          public AsyncTransportWrapper::ReadCallback,
                          public InputHandlerCallback {
 public:
  explicit FizzExampleServer(
      std::shared_ptr<AsyncFizzServer> transport,
      FizzServerAcceptor* acceptor,
      std::shared_ptr<SSLContext> sslCtx)
      : transport_(transport), acceptor_(acceptor), sslCtx_(sslCtx) {}
  void fizzHandshakeSuccess(AsyncFizzServer* server) noexcept override {
    server->setReadCB(this);
    connected_ = true;
    printHandshakeSuccess();
  }

  void fizzHandshakeError(
      AsyncFizzServer* /*server*/,
      exception_wrapper ex) noexcept override {
    LOG(ERROR) << "Handshake error: " << ex.what();
    finish();
  }

  void fizzHandshakeAttemptFallback(
      std::unique_ptr<IOBuf> clientHello) override {
    CHECK(transport_);
    LOG(INFO) << "Fallback attempt";
    auto socket = transport_->getUnderlyingTransport<AsyncSocket>();
    auto evb = socket->getEventBase();
    auto fd = socket->detachFd();
    transport_.reset();
    sslSocket_ =
        AsyncSSLSocket::UniquePtr(new AsyncSSLSocket(sslCtx_, evb, fd));
    sslSocket_->setPreReceivedData(std::move(clientHello));
    sslSocket_->sslAccept(this);
  }

  void handshakeSuc(AsyncSSLSocket* sock) noexcept override {
    LOG(INFO) << "Fallback SSL Handshake success";
    sock->setReadCB(this);
    connected_ = true;
    printFallbackSuccess();
  }

  void handshakeErr(
      AsyncSSLSocket* /*sock*/,
      const AsyncSocketException& ex) noexcept override {
    LOG(ERROR) << "Fallback SSL Handshake error: " << ex.what();
    finish();
  }

  void getReadBuffer(void** bufReturn, size_t* lenReturn) override {
    *bufReturn = readBuf_.data();
    *lenReturn = readBuf_.size();
  }

  void readDataAvailable(size_t len) noexcept override {
    std::cout << std::string(readBuf_.data(), len);
  }

  bool isBufferMovable() noexcept override {
    return true;
  }

  void readBufferAvailable(std::unique_ptr<IOBuf> buf) noexcept override {
    std::cout << StringPiece(buf->coalesce()).str();
  }

  void readEOF() noexcept override {
    LOG(INFO) << "EOF";
    finish();
  }

  void readErr(const AsyncSocketException& ex) noexcept override {
    LOG(ERROR) << "Read error: " << ex.what();
    finish();
  }

  bool connected() const override {
    return connected_;
  }

  void write(std::unique_ptr<IOBuf> msg) override {
    if (transport_) {
      transport_->writeChain(nullptr, std::move(msg));
    } else if (sslSocket_) {
      sslSocket_->writeChain(nullptr, std::move(msg));
    }
  }

  void close() override {
    finish();
  }

 private:
  void printHandshakeSuccess() {
    auto& state = transport_->getState();
    auto serverCert = state.serverCert();
    auto clientCert = state.clientCert();
    LOG(INFO) << "Handshake succeeded.";
    LOG(INFO) << "  TLS Version: " << toString(*state.version());
    LOG(INFO) << "  Cipher Suite:  " << toString(*state.cipher());
    LOG(INFO) << "  Named Group: "
              << (state.group() ? toString(*state.group()) : "(none)");
    LOG(INFO) << "  Signature Scheme: "
              << (state.sigScheme() ? toString(*state.sigScheme()) : "(none)");
    LOG(INFO) << "  PSK: " << toString(*state.pskType());
    LOG(INFO) << "  PSK Mode: "
              << (state.pskMode() ? toString(*state.pskMode()) : "(none)");
    LOG(INFO) << "  Key Exchange Type: " << toString(*state.keyExchangeType());
    LOG(INFO) << "  Early: " << toString(*state.earlyDataType());
    LOG(INFO) << "  Server identity: "
              << (serverCert ? serverCert->getIdentity() : "(none)");
    LOG(INFO) << "  Client Identity: "
              << (clientCert ? clientCert->getIdentity() : "(none)");
    LOG(INFO) << "  Server Certificate Compression: "
              << (state.serverCertCompAlgo()
                      ? toString(*state.serverCertCompAlgo())
                      : "(none)");
    LOG(INFO) << "  ALPN: " << state.alpn().value_or("(none)");
  }

  void printFallbackSuccess() {
    auto serverCert = sslSocket_->getSelfCertificate();
    auto clientCert = sslSocket_->getPeerCertificate();
    auto ssl = sslSocket_->getSSL();
    LOG(INFO) << "Handshake succeeded.";
    LOG(INFO) << "  TLS Version: " << SSL_get_version(ssl);
    LOG(INFO) << "  Cipher:  " << sslSocket_->getNegotiatedCipherName();
    LOG(INFO) << "  Signature Algorithm: "
              << sslSocket_->getSSLCertSigAlgName();
    LOG(INFO) << "  Server identity: "
              << (serverCert ? serverCert->getIdentity() : "(none)");
    LOG(INFO) << "  Client Identity: "
              << (clientCert ? clientCert->getIdentity() : "(none)");
  }

  void finish() {
    if (transport_ || sslSocket_) {
      transport_.reset();
      sslSocket_.reset();
      acceptor_->done();
    }
  }

  std::shared_ptr<AsyncFizzServer> transport_;
  AsyncSSLSocket::UniquePtr sslSocket_;
  FizzServerAcceptor* acceptor_;
  std::shared_ptr<SSLContext> sslCtx_;
  std::array<char, 8192> readBuf_;
  bool connected_{false};
};

FizzServerAcceptor::FizzServerAcceptor(
    uint16_t port,
    std::shared_ptr<FizzServerContext> serverCtx,
    bool loop,
    EventBase* evb,
    std::shared_ptr<SSLContext> sslCtx)
    : loop_(loop), evb_(evb), ctx_(serverCtx), sslCtx_(sslCtx) {
  socket_ = AsyncServerSocket::UniquePtr(new AsyncServerSocket(evb_));
  socket_->bind(port);
  socket_->listen(100);
  socket_->addAcceptCallback(this, evb_);
  socket_->startAccepting();
  LOG(INFO) << "Started listening on " << socket_->getAddress();
}

void FizzServerAcceptor::connectionAccepted(
    int fd,
    const SocketAddress& clientAddr) noexcept {
  LOG(INFO) << "Connection accepted from " << clientAddr;
  auto sock = new AsyncSocket(evb_, fd);
  std::shared_ptr<AsyncFizzServer> transport = AsyncFizzServer::UniquePtr(
      new AsyncFizzServer(AsyncSocket::UniquePtr(sock), ctx_));
  socket_->pauseAccepting();
  auto serverCb = std::make_unique<FizzExampleServer>(transport, this, sslCtx_);
  inputHandler_ = std::make_unique<TerminalInputHandler>(evb_, serverCb.get());
  cb_ = std::move(serverCb);
  transport->accept(cb_.get());
}

void FizzServerAcceptor::acceptError(const std::exception& ex) noexcept {
  LOG(ERROR) << "Failed to accept connection: " << ex.what();
  if (!loop_) {
    evb_->terminateLoopSoon();
  }
}

void FizzServerAcceptor::done() {
  cb_.reset();
  inputHandler_.reset();
  if (loop_) {
    socket_->startAccepting();
  } else {
    socket_.reset();
  }
}

} // namespace

int fizzServerCommand(const std::vector<std::string>& args) {
  uint16_t port = 8443;
  Optional<std::vector<CipherSuite>> ciphers;
  std::string certPath;
  std::string keyPath;
  std::string keyPass;
  ClientAuthMode clientAuthMode = ClientAuthMode::None;
  std::string caPaths;
  std::string caFile;
  bool early = false;
  std::vector<std::string> alpns;
  folly::Optional<std::vector<CertificateCompressionAlgorithm>> compAlgos;
  bool loop = false;
  bool fallback = false;

  // clang-format off
  FizzArgHandlerMap handlers = {
    {"-accept", {true, [&port](const std::string& arg) {
        port = portFromString(arg, true);
    }}},
    {"-ciphers", {true, [&ciphers](const std::string& arg) {
        try {
          ciphers = fromCSV<CipherSuite>(arg);
        }
        catch (const std::exception& e) {
          LOG(ERROR) << "Error parsing cipher suites: " << e.what();
          throw;
        }
    }}},
    {"-cert", {true, [&certPath](const std::string& arg) { certPath = arg; }}},
    {"-key", {true, [&keyPath](const std::string& arg) { keyPath = arg; }}},
    {"-pass", {true, [&keyPass](const std::string& arg) { keyPass = arg; }}},
    {"-requestcert", {false, [&clientAuthMode](const std::string&) {
      clientAuthMode = ClientAuthMode::Optional;
    }}},
    {"-requirecert", {false, [&clientAuthMode](const std::string&) {
      clientAuthMode = ClientAuthMode::Required;
    }}},
    {"-capaths", {true, [&caPaths](const std::string& arg) { caPaths = arg; }}},
    {"-cafile", {true, [&caFile](const std::string& arg) { caFile = arg; }}},
    {"-early", {false, [&early](const std::string&) { early = true; }}},
    {"-alpn", {true, [&alpns](const std::string& arg) {
        alpns.clear();
        folly::split(",", arg, alpns);
    }}},
    {"-certcompression", {true, [&compAlgos](const std::string& arg) {
        try {
          compAlgos = fromCSV<CertificateCompressionAlgorithm>(arg);
        } catch (const std::exception& e) {
          LOG(ERROR) << "Error parsing certificate compression algorithms: " << e.what();
          throw;
        }
    }}},
    {"-loop", {false, [&loop](const std::string&) { loop = true; }}},
    {"-quiet", {false, [](const std::string&) {
        FLAGS_minloglevel = google::GLOG_ERROR;
    }}},
    {"-fallback", {false, [&fallback](const std::string&) {
        fallback = true;
    }}}
  };
  // clang-format on

  try {
    if (parseArguments(args, handlers, printUsage)) {
      // Parsing failed, return
      return 1;
    }
  } catch (const std::exception& e) {
    LOG(ERROR) << "Error: " << e.what();
    return 1;
  }

  // Sanity check input.
  if (certPath.empty() != keyPath.empty()) {
    LOG(ERROR) << "-cert and -key are both required when specified";
    return 1;
  }

  EventBase evb;
  std::shared_ptr<const CertificateVerifier> verifier;

  if (clientAuthMode != ClientAuthMode::None) {
    // Initialize CA store first, if given.
    folly::ssl::X509StoreUniquePtr storePtr;
    if (!caPaths.empty() || !caFile.empty()) {
      storePtr.reset(X509_STORE_new());
      auto caFilePtr = caFile.empty() ? nullptr : caFile.c_str();
      auto caPathPtr = caPaths.empty() ? nullptr : caPaths.c_str();

      if (X509_STORE_load_locations(storePtr.get(), caFilePtr, caPathPtr) ==
          0) {
        LOG(ERROR) << "Failed to load CA certificates";
        return 1;
      }
    }

    verifier = std::make_shared<const DefaultCertificateVerifier>(
        VerificationContext::Server, std::move(storePtr));
  }

  auto serverContext = std::make_shared<FizzServerContext>();
  if (ciphers) {
    serverContext->setSupportedCiphers({*ciphers});
  }
  serverContext->setClientAuthMode(clientAuthMode);
  serverContext->setClientCertVerifier(verifier);

  auto ticketCipher = std::make_shared<AeadTicketCipher<
      OpenSSLEVPCipher<AESGCM128>,
      TicketCodec<CertificateStorage::X509>,
      HkdfImpl<Sha256>>>();
  auto ticketSeed = RandomGenerator<32>().generateRandom();
  ticketCipher->setTicketSecrets({{range(ticketSeed)}});
  serverContext->setTicketCipher(ticketCipher);

  // Store a vector of compressors and algorithms for which there are
  // compressors.
  auto certManager = std::make_unique<CertManager>();
  std::vector<std::shared_ptr<CertificateCompressor>> compressors;
  std::vector<CertificateCompressionAlgorithm> finalAlgos;
  if (compAlgos) {
    for (const auto& algo : *compAlgos) {
      switch (algo) {
        case CertificateCompressionAlgorithm::zlib:
          compressors.push_back(std::make_shared<ZlibCertificateCompressor>(9));
          finalAlgos.push_back(algo);
          break;
        default:
          LOG(WARNING) << "Don't know what compressor to use for "
                       << toString(algo) << ", ignoring.";
          break;
      }
    }
  }
  serverContext->setSupportedCompressionAlgorithms(finalAlgos);

  if (!certPath.empty()) {
    std::string certData;
    std::string keyData;
    if (!readFile(certPath.c_str(), certData)) {
      LOG(ERROR) << "Failed to read certificate";
      return 1;
    } else if (!readFile(keyPath.c_str(), keyData)) {
      LOG(ERROR) << "Failed to read private key";
      return 1;
    }
    std::unique_ptr<SelfCert> cert;
    if (!keyPass.empty()) {
      cert = CertUtils::makeSelfCert(certData, keyData, keyPass, compressors);
    } else {
      cert = CertUtils::makeSelfCert(certData, keyData, compressors);
    }
    certManager->addCert(std::move(cert), true);
  } else {
    auto certData = fizz::test::createCert("fizz-self-signed", false, nullptr);
    std::vector<folly::ssl::X509UniquePtr> certChain;
    certChain.push_back(std::move(certData.cert));
    auto cert = std::make_unique<SelfCertImpl<KeyType::P256>>(
        std::move(certData.key), std::move(certChain), compressors);
    certManager->addCert(std::move(cert), true);
  }
  serverContext->setCertManager(std::move(certManager));

  if (early) {
    serverContext->setEarlyDataSettings(
        true,
        {std::chrono::seconds(-10), std::chrono::seconds(10)},
        std::make_shared<SlidingBloomReplayCache>(240, 140000, 0.0005, &evb));
  }

  std::shared_ptr<SSLContext> sslContext;
  if (fallback) {
    if (certPath.empty()) {
      LOG(ERROR) << "Fallback mode requires explicit certificates";
      return 1;
    }
    sslContext = std::make_shared<SSLContext>();
    sslContext->loadCertKeyPairFromFiles(certPath.c_str(), keyPath.c_str());
    SSL_CTX_set_ecdh_auto(sslContext->getSSLCtx(), 1);
  }
  serverContext->setVersionFallbackEnabled(fallback);

  if (!alpns.empty()) {
    serverContext->setSupportedAlpns(std::move(alpns));
  }

  serverContext->setSupportedVersions(
      {ProtocolVersion::tls_1_3, ProtocolVersion::tls_1_3_28});
  FizzServerAcceptor acceptor(port, serverContext, loop, &evb, sslContext);
  evb.loop();
  return 0;
}

} // namespace tool
} // namespace fizz
