/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/protocol/BrotliCertificateCompressor.h>
#include <enc/encode.h>

using namespace folly;

namespace fizz {

BrotliCertificateCompressor::BrotliCertificateCompressor(
    int compressLevel,
    int windowSize)
    : level_(compressLevel), windowSize_(windowSize) {}

BrotliCertificateCompressor::BrotliCertificateCompressor()
    : level_(11), windowSize_(22) {}

CertificateCompressionAlgorithm BrotliCertificateCompressor::getAlgorithm()
    const {
  return CertificateCompressionAlgorithm::brotli;
}

namespace {
class IOBufIn : public brotli::BrotliIn {
 public:
  explicit IOBufIn(IOBuf* src)
      : originalLength_(src->computeChainDataLength()), cursor_(src) {}

  const void* Read(size_t n, size_t* nread) override {
    if (cursor_.isAtEnd()) {
      return nullptr;
    }
    if (n == 0) {
      *nread = 0;
      return buf_.data();
    }
    buf_.resize(std::min(n, cursor_.totalLength()));
    *nread = cursor_.pullAtMost(buf_.data(), buf_.size());
    return buf_.data();
  }

  const size_t originalLength() {
    return originalLength_;
  }

 private:
  std::vector<char> buf_{0};
  size_t originalLength_;
  folly::io::Cursor cursor_;
};

class IOBufOut : public brotli::BrotliOut {
 public:
  bool Write(const void* buf, size_t n) override {
    queue_.append(buf, n);
    return true;
  }

  std::unique_ptr<IOBuf> getBuffer() {
    return queue_.move();
  }

 private:
  IOBufQueue queue_;
};
} // namespace

CompressedCertificate BrotliCertificateCompressor::compress(
    const CertificateMsg& cert) {
  auto encoded = encode(cert);
  brotli::BrotliParams params;
  params.quality = level_;
  params.lgwin = windowSize_;

  IOBufIn inputStream(encoded.get());
  IOBufOut outputStream;
  auto status = BrotliCompress(params, &inputStream, &outputStream);

  if (status != 1) {
    throw std::runtime_error("Failed to compress certificate");
  }

  auto compressedCert = outputStream.getBuffer();
  if (!compressedCert) {
    throw std::runtime_error("Failed to compress certificate: no output");
  }
  CompressedCertificate cc;
  cc.uncompressed_length = inputStream.originalLength();
  cc.algorithm = getAlgorithm();
  cc.compressed_certificate_message = std::move(compressedCert);
  return cc;
}

} // namespace fizz
