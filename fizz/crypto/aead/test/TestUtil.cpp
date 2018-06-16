/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/crypto/aead/test/TestUtil.h>

#include <fizz/crypto/aead/IOBufUtil.h>

using namespace folly;

namespace fizz {
namespace test {

// Converts the hex encoded string to an IOBuf.
std::unique_ptr<folly::IOBuf> toIOBuf(std::string hexData) {
  std::string out;
  CHECK(folly::unhexlify(hexData, out));
  return folly::IOBuf::copyBuffer(out);
}

std::unique_ptr<IOBuf> chunkIOBuf(std::unique_ptr<IOBuf> input, size_t chunks) {
  // create IOBuf chunks
  size_t inputLen = input->computeChainDataLength();
  size_t chunkLen = floor((double)inputLen / (double)chunks);
  std::unique_ptr<IOBuf> chunked;

  for (size_t i = 0; i < chunks - 1; ++i) {
    auto buf = IOBuf::create(chunkLen);
    buf->append(chunkLen);
    if (!chunked) {
      chunked = std::move(buf);
    } else {
      chunked->prependChain(std::move(buf));
    }
  }

  size_t remainLen = inputLen - (chunks - 1) * chunkLen;
  auto remain = IOBuf::create(remainLen);
  remain->append(remainLen);
  chunked->prependChain(std::move(remain));

  transformBuffer(
      *input, *chunked, [](uint8_t* out, const uint8_t* in, size_t len) {
        memcpy(out, in, len);
      });

  CHECK_EQ(chunks, chunked->countChainElements());
  return chunked;
}
} // namespace test
} // namespace fizz
