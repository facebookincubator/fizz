/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/protocol/BrotliCertificateDecompressor.h>
#include <dec/decode.h>

using namespace folly;

namespace fizz {

CertificateCompressionAlgorithm BrotliCertificateDecompressor::getAlgorithm()
    const {
  return CertificateCompressionAlgorithm::brotli;
}

CertificateMsg BrotliCertificateDecompressor::decompress(
    const CompressedCertificate& cc) {
  if (cc.algorithm != getAlgorithm()) {
    throw std::runtime_error(
        "Compressed certificate uses non-brotli algorithm: " +
        toString(cc.algorithm));
  }

  if (cc.uncompressed_length > kMaxHandshakeSize) {
    throw std::runtime_error(
        "Compressed certificate exceeds maximum certificate message size");
  }

  auto rawCertMessage = IOBuf::create(cc.uncompressed_length);
  size_t size = cc.uncompressed_length;
  auto compRange = cc.compressed_certificate_message->coalesce();
  auto status = BrotliDecompressBuffer(
      compRange.size(),
      compRange.data(),
      &size,
      rawCertMessage->writableData());
  if (status != BrotliResult::BROTLI_RESULT_SUCCESS) {
    throw std::runtime_error("Decompressing certificate failed");
  } else if (size != cc.uncompressed_length) {
    throw std::runtime_error("Uncompressed length incorrect");
  }

  rawCertMessage->append(size);
  return decode<CertificateMsg>(std::move(rawCertMessage));
}

} // namespace fizz
