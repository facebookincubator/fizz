/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <folly/Benchmark.h>
#include <folly/String.h>
#include <folly/init/Init.h>
#include <folly/io/Cursor.h>
#include <folly/io/IOBuf.h>

#include <fizz/record/Extensions.h>
#include <fizz/record/test/ClientHelloTestData.h>

using namespace fizz;
using namespace fizz::test;

namespace {

ClientHello decodeClientHello(const folly::IOBuf& buf) {
  folly::io::Cursor cursor(&buf);
  ClientHello chlo;
  Error err;
  FIZZ_THROW_ON_ERROR(decode(chlo, err, cursor), err);
  return chlo;
}

template <class T>
void parseExtension(const ClientHello& chlo) {
  folly::Optional<T> ext;
  Error err;
  FIZZ_THROW_ON_ERROR(getExtension(ext, err, chlo.extensions), err);
  folly::doNotOptimizeAway(ext);
}

void parseServerExtensions(const ClientHello& chlo) {
  parseExtension<SupportedVersions>(chlo);
  parseExtension<Cookie>(chlo);
  parseExtension<ClientPresharedKey>(chlo);
  parseExtension<PskKeyExchangeModes>(chlo);
  parseExtension<ClientEarlyData>(chlo);
  parseExtension<SupportedGroups>(chlo);
  parseExtension<ClientKeyShare>(chlo);
  parseExtension<ProtocolNameList>(chlo);
  parseExtension<SignatureAlgorithms>(chlo);
  parseExtension<ServerNameList>(chlo);
  parseExtension<CertificateCompressionAlgorithms>(chlo);
}

void decodeOnly(size_t iters, const folly::IOBuf& buf) {
  for (size_t i = 0; i < iters; ++i) {
    folly::doNotOptimizeAway(decodeClientHello(buf));
  }
}

void decodeAndParseExtensions(size_t iters, const folly::IOBuf& buf) {
  for (size_t i = 0; i < iters; ++i) {
    parseServerExtensions(decodeClientHello(buf));
  }
}

const folly::IOBuf kFirefoxBuf{
    folly::IOBuf::COPY_BUFFER,
    folly::unhexlify(kFirefoxClientHello)};
const folly::IOBuf kPskBuf{
    folly::IOBuf::COPY_BUFFER,
    folly::unhexlify(kPskClientHello)};
const folly::IOBuf kSsl3Buf{
    folly::IOBuf::COPY_BUFFER,
    folly::unhexlify(kSsl3ClientHello)};

} // namespace

BENCHMARK_NAMED_PARAM(decodeOnly, firefox, kFirefoxBuf)
BENCHMARK_NAMED_PARAM(decodeOnly, psk, kPskBuf)
BENCHMARK_NAMED_PARAM(decodeOnly, ssl3, kSsl3Buf)
BENCHMARK_DRAW_LINE();
BENCHMARK_NAMED_PARAM(decodeAndParseExtensions, firefox, kFirefoxBuf)
BENCHMARK_NAMED_PARAM(decodeAndParseExtensions, psk, kPskBuf)

int main(int argc, char** argv) {
  const folly::Init init(&argc, &argv);
  folly::runBenchmarks();
  return 0;
}
