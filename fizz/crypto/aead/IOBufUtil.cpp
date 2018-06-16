/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/crypto/aead/IOBufUtil.h>

using namespace folly;

namespace fizz {

std::unique_ptr<IOBuf> trimBytes(IOBuf& buf, size_t trim) {
  auto trimmedBytes = IOBuf::create(trim);
  trimmedBytes->append(trim);

  size_t currentTrim = trim;
  IOBuf* current = buf.prev();
  size_t chainElements = buf.countChainElements();
  for (size_t i = 0; i < chainElements && currentTrim != 0; ++i) {
    size_t toTrim =
        std::min(currentTrim, static_cast<size_t>(current->length()));
    memcpy(
        trimmedBytes->writableData() + (currentTrim - toTrim),
        current->data() + (current->length() - toTrim),
        toTrim);
    current->trimEnd(toTrim);
    currentTrim -= toTrim;
    current = current->prev();
  }
  return trimmedBytes;
}

void XOR(ByteRange first, MutableByteRange second) {
  CHECK_EQ(first.size(), second.size());
  for (size_t i = 0; i < first.size(); ++i) {
    second[i] ^= first[i];
  }
};
} // namespace fizz
