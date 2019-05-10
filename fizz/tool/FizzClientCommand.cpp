/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/client/AsyncFizzClient.h>
#ifdef FIZZ_TOOL_ENABLE_BROTLI
#include <fizz/protocol/BrotliCertificateDecompressor.h>
#endif
#include <fizz/protocol/ZlibCertificateDecompressor.h>
#ifdef FIZZ_TOOL_ENABLE_ZSTD
#include <fizz/protocol/ZstdCertificateDecompressor.h>
#endif
#include <fizz/tool/FizzCommandCommon.h>
#include <fizz/util/Parse.h>
#include <folly/FileUtil.h>
#include <folly/Format.h>
#include <folly/io/async/SSLContext.h>

#include <iostream>
#include <string>
#include <vector>

using namespace fizz::client;
using namespace folly;

namespace fizz {
namespace tool {
namespace {

void printUsage() {
  // clang-format off
  std::cerr
    << "Usage: s_client args\n"
    << "\n"
    << "Supported arguments:\n"
    << " -host host               (use connect instead)\n"
    << " -port port               (use connect instead)\n"
    << " -connect host:port       (set the address to connect to. Default: localhost:4433)\n"
    << " -verify                  (enable server cert verification. Default: false)\n"
    << " -cert cert               (PEM format client certificate to send if requested. Default: none)\n"
    << " -key key                 (PEM format private key for client certificate. Default: none)\n"
    << " -pass password           (private key password. Default: none)\n"
    << " -capaths d1:...          (colon-separated paths to directories of CA certs used for verification)\n"
    << " -cafile file             (path to bundle of CA certs used for verification)\n"
    << " -reconnect               (after connecting, open another connection using a psk. Default: false)\n"
    << " -servername name         (server name to send in SNI. Default: same as host)\n"
    << " -alpn alpn1:...          (colon-separated list of ALPNs to send. Default: none)\n"
    << " -ciphers c1:...          (colon-separated list of ciphers in preference order. Default:\n"
    << "                           TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256)\n"
    << " -certcompression a1:...  (enables certificate compression support for given algorithms. Default: None)\n"
    << " -early                   (enables sending early data during resumption. Default: false)\n"
    << " -quiet                   (hide informational logging. Default: false)\n"
    << " -v verbosity             (set verbose log level for VLOG macros. Default: 0)\n"
    << " -vmodule m1=N,...        (set per-module verbose log level for VLOG macros. Default: none)\n"
    << " -httpproxy host:port     (set an HTTP proxy to use. Default: none)\n";
  // clang-format on
}

class Connection : public AsyncSocket::ConnectCallback,
                   public AsyncFizzClient::HandshakeCallback,
                   public AsyncTransportWrapper::ReadCallback,
                   public AsyncTransport::ReplaySafetyCallback,
                   public InputHandlerCallback,
                   public SecretCollector {
 public:
  Connection(
      EventBase* evb,
      std::shared_ptr<FizzClientContext> clientContext,
      Optional<std::string> sni,
      std::shared_ptr<const CertificateVerifier> verifier,
      bool willResume,
      std::string proxyTarget)
      : evb_(evb),
        clientContext_(clientContext),
        sni_(sni),
        verifier_(std::move(verifier)),
        willResume_(willResume),
        proxyTarget_(proxyTarget) {}

  void connect(const SocketAddress& addr) {
    sock_ = AsyncSocket::UniquePtr(new AsyncSocket(evb_));
    sock_->connect(this, addr);
  }

  void close() override {
    if (transport_) {
      transport_->close();
    } else if (sock_) {
      sock_->close();
    }
  }

  void connectErr(const AsyncSocketException& ex) noexcept override {
    LOG(ERROR) << "Connect error: " << ex.what();
    evb_->terminateLoopSoon();
  }

  void connectSuccess() noexcept override {
    LOG(INFO) << (willResume_ ? "Initial connection" : "Connection")
              << " established.";
    if (!proxyTarget_.empty()) {
      auto connectCommand = IOBuf::create(0);
      folly::io::Appender appender(connectCommand.get(), 10);
      format(
          "CONNECT {} HTTP/1.1\r\n"
          "Host: {}\r\n\r\n",
          proxyTarget_,
          proxyTarget_)(appender);
      sock_->setReadCB(this);
      sock_->writeChain(nullptr, std::move(connectCommand));
    } else {
      doHandshake();
    }
  }

  void doHandshake() {
    transport_ = AsyncFizzClient::UniquePtr(
        new AsyncFizzClient(std::move(sock_), clientContext_));
    transport_->setSecretCallback(this);
    transport_->connect(this, verifier_, sni_, sni_);
  }

  void fizzHandshakeSuccess(AsyncFizzClient* /*client*/) noexcept override {
    if (transport_->isReplaySafe()) {
      printHandshakeSuccess();
    } else {
      LOG(INFO) << "Early handshake success.";
      transport_->setReplaySafetyCallback(this);
    }
    transport_->setReadCB(this);
  }

  void fizzHandshakeError(
      AsyncFizzClient* /*client*/,
      exception_wrapper ex) noexcept override {
    LOG(ERROR) << "Handshake error: " << ex.what();
    evb_->terminateLoopSoon();
  }

  void getReadBuffer(void** bufReturn, size_t* lenReturn) override {
    *bufReturn = readBuf_.data();
    *lenReturn = readBuf_.size();
  }

  void readDataAvailable(size_t len) noexcept override {
    readBufferAvailable(IOBuf::copyBuffer(readBuf_.data(), len));
  }

  bool isBufferMovable() noexcept override {
    return true;
  }

  void readBufferAvailable(std::unique_ptr<IOBuf> buf) noexcept override {
    if (!transport_) {
      if (!proxyResponseBuffer_) {
        proxyResponseBuffer_ = std::move(buf);
      } else {
        proxyResponseBuffer_->prependChain(std::move(buf));
      }
      auto currentContents = StringPiece(proxyResponseBuffer_->coalesce());
      auto statusEndPos = currentContents.find("\r\n");
      if (statusEndPos == std::string::npos) {
        // No complete line yet
        return;
      }
      auto statusLine = currentContents.subpiece(0, statusEndPos).str();
      unsigned int httpVer;
      unsigned int httpStatus;
      if (sscanf(statusLine.c_str(), "HTTP/1.%u %u", &httpVer, &httpStatus) !=
          2) {
        LOG(ERROR) << "Failed to parse status: " << statusLine;
        close();
      }

      if (httpStatus / 100 != 2) {
        LOG(ERROR) << "Got non-200 status: " << httpStatus;
        close();
      }

      auto endPos = currentContents.find("\r\n\r\n");
      if (endPos != std::string::npos) {
        endPos += 4;
        auto remainder = currentContents.subpiece(endPos);
        sock_->setReadCB(nullptr);
        if (remainder.size()) {
          sock_->setPreReceivedData(IOBuf::copyBuffer(remainder));
        }
        doHandshake();
      }
    } else {
      std::cout << StringPiece(buf->coalesce()).str();
    }
  }

  void readEOF() noexcept override {
    LOG(INFO) << (willResume_ ? "Initial EOF" : "EOF");
    if (!willResume_) {
      evb_->terminateLoopSoon();
    }
  }

  void readErr(const AsyncSocketException& ex) noexcept override {
    LOG(ERROR) << "Read error: " << ex.what();
    evb_->terminateLoopSoon();
  }

  void onReplaySafe() override {
    printHandshakeSuccess();
  }

  bool connected() const override {
    return transport_ && !transport_->connecting() && transport_->good();
  }

  void write(std::unique_ptr<IOBuf> msg) override {
    if (transport_) {
      transport_->writeChain(nullptr, std::move(msg));
    }
  }

 private:
  void printHandshakeSuccess() {
    auto& state = transport_->getState();
    auto serverCert = state.serverCert();
    auto clientCert = state.clientCert();
    LOG(INFO) << (willResume_ ? "Initial handshake" : "Handshake")
              << " succeeded.";
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
    LOG(INFO) << "  Server Identity: "
              << (serverCert ? serverCert->getIdentity() : "(none)");
    LOG(INFO) << "  Client Identity: "
              << (clientCert ? clientCert->getIdentity() : "(none)");
    if (serverCert) {
      folly::ssl::BioUniquePtr bio(BIO_new(BIO_s_mem()));
      if (!PEM_write_bio_X509(bio.get(), serverCert->getX509().get())) {
        LOG(ERROR) << "  Couldn't convert server certificate to PEM: "
                   << SSLContext::getErrors();
      } else {
        BUF_MEM* bptr = nullptr;
        BIO_get_mem_ptr(bio.get(), &bptr);
        LOG(INFO) << "  Server Certificate:\n"
                  << std::string(bptr->data, bptr->length);
      }
    }

    if (clientCert) {
      folly::ssl::BioUniquePtr bio(BIO_new(BIO_s_mem()));
      if (!PEM_write_bio_X509(bio.get(), clientCert->getX509().get())) {
        LOG(ERROR) << "  Couldn't convert client certificate to PEM: "
                   << SSLContext::getErrors();
      } else {
        BUF_MEM* bptr = nullptr;
        BIO_get_mem_ptr(bio.get(), &bptr);
        LOG(INFO) << "  Client Certificate:\n"
                  << std::string(bptr->data, bptr->length);
      }
    }
    LOG(INFO) << "  Server Certificate Compression: "
              << (state.serverCertCompAlgo()
                      ? toString(*state.serverCertCompAlgo())
                      : "(none)");
    LOG(INFO) << "  ALPN: " << state.alpn().value_or("(none)");
    LOG(INFO) << "  Client Random: " << folly::hexlify(state.clientRandom());
    LOG(INFO) << "  Secrets:";
    LOG(INFO) << "    External PSK Binder: " << secretStr(externalPskBinder_);
    LOG(INFO) << "    Resumption PSK Binder: "
              << secretStr(resumptionPskBinder_);
    LOG(INFO) << "    Early Exporter: " << secretStr(earlyExporterSecret_);
    LOG(INFO) << "    Early Client Data: "
              << secretStr(clientEarlyTrafficSecret_);
    LOG(INFO) << "    Client Handshake: "
              << secretStr(clientHandshakeTrafficSecret_);
    LOG(INFO) << "    Server Handshake: "
              << secretStr(serverHandshakeTrafficSecret_);
    LOG(INFO) << "    Exporter Master: " << secretStr(exporterMasterSecret_);
    LOG(INFO) << "    Resumption Master: "
              << secretStr(resumptionMasterSecret_);
    LOG(INFO) << "    Client Traffic: " << secretStr(clientAppTrafficSecret_);
    LOG(INFO) << "    Server Traffic: " << secretStr(serverAppTrafficSecret_);
  }

  EventBase* evb_;
  std::shared_ptr<FizzClientContext> clientContext_;
  Optional<std::string> sni_;
  std::shared_ptr<const CertificateVerifier> verifier_;
  AsyncSocket::UniquePtr sock_;
  AsyncFizzClient::UniquePtr transport_;
  bool willResume_{false};
  std::array<char, 8192> readBuf_;
  std::string proxyTarget_;
  std::unique_ptr<IOBuf> proxyResponseBuffer_;
};

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

} // namespace

int fizzClientCommand(const std::vector<std::string>& args) {
  std::string host = "localhost";
  uint16_t port = 4433;
  bool verify = false;
  std::string certPath;
  std::string keyPath;
  std::string keyPass;
  std::string caPath;
  std::string caFile;
  bool reconnect = false;
  std::string customSNI;
  std::vector<std::string> alpns;
  folly::Optional<std::vector<CertificateCompressionAlgorithm>> compAlgos;
  bool early = false;
  std::string proxyHost = "";
  uint16_t proxyPort = 0;
  std::vector<CipherSuite> ciphers {
    CipherSuite::TLS_AES_128_GCM_SHA256,
    CipherSuite::TLS_AES_256_GCM_SHA384,
#if FOLLY_OPENSSL_HAS_CHACHA
    CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
#endif
  };

  // clang-format off
  FizzArgHandlerMap handlers = {
    {"-host", {true, [&host](const std::string& arg) { host = arg; }}},
    {"-port", {true, [&port](const std::string& arg) {
        port = portFromString(arg, false);
    }}},
    {"-connect", {true, [&host, &port](const std::string& arg) {
        std::tie(host, port) = hostPortFromString(arg);
     }}},
    {"-verify", {false, [&verify](const std::string&) { verify = true; }}},
    {"-cert", {true, [&certPath](const std::string& arg) { certPath = arg; }}},
    {"-key", {true, [&keyPath](const std::string& arg) { keyPath = arg; }}},
    {"-pass", {true, [&keyPass](const std::string& arg) { keyPass = arg; }}},
    {"-capath", {true, [&caPath](const std::string& arg) { caPath = arg; }}},
    {"-cafile", {true, [&caFile](const std::string& arg) { caFile = arg; }}},
    {"-reconnect", {false, [&reconnect](const std::string&) {
        reconnect = true;
    }}},
    {"-servername", {true, [&customSNI](const std::string& arg) {
        customSNI = arg;
    }}},
    {"-alpn", {true, [&alpns](const std::string& arg) {
        alpns.clear();
        folly::split(",", arg, alpns);
    }}},
    {"-certcompression", {true, [&compAlgos](const std::string& arg) {
        try {
          compAlgos = splitParse<CertificateCompressionAlgorithm>(arg);
        } catch (const std::exception& e) {
          LOG(ERROR) << "Error parsing certificate compression algorithms: " << e.what();
          throw;
        }
    }}},
    {"-early", {false, [&early](const std::string&) { early = true; }}},
    {"-quiet", {false, [](const std::string&) {
        FLAGS_minloglevel = google::GLOG_ERROR;
    }}},
    {"-httpproxy", {true, [&proxyHost, &proxyPort] (const std::string& arg) {
        std::tie(proxyHost, proxyPort) = hostPortFromString(arg);
    }}},
    {"-ciphers", {true, [&ciphers](const std::string& arg) {
        ciphers = splitParse<CipherSuite>(arg);
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
  auto clientContext = std::make_shared<FizzClientContext>();

  if (!alpns.empty()) {
    clientContext->setSupportedAlpns(std::move(alpns));
  }

  clientContext->setSupportedCiphers(std::move(ciphers));

  clientContext->setSupportedVersions(
      {ProtocolVersion::tls_1_3, ProtocolVersion::tls_1_3_28});
  clientContext->setSendEarlyData(early);

  if (compAlgos) {
    auto mgr = std::make_shared<CertDecompressionManager>();
    std::vector<std::shared_ptr<CertificateDecompressor>> decompressors;
    for (const auto& algo : *compAlgos) {
      switch (algo) {
        case CertificateCompressionAlgorithm::zlib:
          decompressors.push_back(
              std::make_shared<ZlibCertificateDecompressor>());
          break;
#ifdef FIZZ_TOOL_ENABLE_BROTLI
        case CertificateCompressionAlgorithm::brotli:
          decompressors.push_back(
              std::make_shared<BrotliCertificateDecompressor>());
          break;
#endif
#ifdef FIZZ_TOOL_ENABLE_ZSTD
        case CertificateCompressionAlgorithm::zstd:
          decompressors.push_back(
              std::make_shared<ZstdCertificateDecompressor>());
          break;
#endif
        default:
          LOG(WARNING) << "Don't know what decompressor to use for "
                       << toString(algo) << ", ignoring...";
          break;
      }
    }
    mgr->setDecompressors(decompressors);
    clientContext->setCertDecompressionManager(std::move(mgr));
  }

  if (verify) {
    // Initialize CA store first, if given.
    folly::ssl::X509StoreUniquePtr storePtr;
    if (!caPath.empty() || !caFile.empty()) {
      storePtr.reset(X509_STORE_new());
      auto caFilePtr = caFile.empty() ? nullptr : caFile.c_str();
      auto caPathPtr = caPath.empty() ? nullptr : caPath.c_str();

      if (X509_STORE_load_locations(storePtr.get(), caFilePtr, caPathPtr) ==
          0) {
        LOG(ERROR) << "Failed to load CA certificates";
        return 1;
      }
    }

    verifier = std::make_shared<const DefaultCertificateVerifier>(
        VerificationContext::Client, std::move(storePtr));
  }

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
      cert = CertUtils::makeSelfCert(certData, keyData, keyPass);
    } else {
      cert = CertUtils::makeSelfCert(certData, keyData);
    }
    clientContext->setClientCertificate(std::move(cert));
  }

  try {
    auto sni = customSNI.empty() ? host : customSNI;
    auto connectHost = proxyHost.empty() ? host : proxyHost;
    auto connectPort = proxyHost.empty() ? port : proxyPort;
    auto proxiedHost = proxyHost.empty()
        ? std::string()
        : folly::to<std::string>(host, ":", port);
    SocketAddress addr(connectHost, connectPort, true);
    Connection conn(&evb, clientContext, sni, verifier, reconnect, proxiedHost);
    Connection resumptionConn(
        &evb, clientContext, sni, verifier, false, proxiedHost);
    Connection* inputTarget = &conn;
    if (reconnect) {
      auto pskCache = std::make_shared<ResumptionPskCache>(
          &evb, [&conn, &resumptionConn, addr]() {
            conn.close();
            resumptionConn.connect(addr);
          });
      clientContext->setPskCache(pskCache);
      inputTarget = &resumptionConn;
    }
    TerminalInputHandler input(&evb, inputTarget);
    conn.connect(addr);
    evb.loop();
  } catch (const std::exception& e) {
    LOG(ERROR) << "Error: " << e.what();
    return 1;
  }

  return 0;
}

} // namespace tool
} // namespace fizz
