// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

#include <fizz/record/BufAndPaddingPolicy.h>

namespace fizz {

Buf getBufToEncrypt(folly::IOBufQueue& queue, uint16_t maxRecord) {
  if (queue.front()->length() > maxRecord) {
    return queue.splitAtMost(maxRecord);
  } else if (queue.front()->length() >= kMinSuggestedRecordSize) {
    return queue.pop_front();
  } else {
    return queue.splitAtMost(std::min(maxRecord, kMinSuggestedRecordSize));
  }
}

std::pair<Buf, uint16_t> BufAndModuloPaddingPolicy::getBufAndPaddingToEncrypt(
    folly::IOBufQueue& queue,
    uint16_t maxRecord) const {
  Buf dataBuf = getBufToEncrypt(queue, maxRecord);
  if (paddingModulo_ > 0) {
    uint16_t lengthRemaining = maxRecord - dataBuf->computeChainDataLength();
    return std::make_pair(std::move(dataBuf), lengthRemaining % paddingModulo_);
  } else {
    return std::make_pair(std::move(dataBuf), 0);
  }
}

std::pair<Buf, uint16_t> BufAndConstPaddingPolicy::getBufAndPaddingToEncrypt(
    folly::IOBufQueue& queue,
    uint16_t maxRecord) const {
  Buf dataBuf = getBufToEncrypt(queue, maxRecord);
  uint16_t paddingSize = 0;
  if (paddingSize_ > 0) {
    uint16_t dataLength = dataBuf->computeChainDataLength();
    paddingSize =
        std::min(paddingSize_, static_cast<uint16_t>(maxRecord - dataLength));
  }
  return std::make_pair(std::move(dataBuf), paddingSize);
}

} // namespace fizz
