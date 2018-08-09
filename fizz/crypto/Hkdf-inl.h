/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

namespace fizz {

template <typename Hash>
inline std::vector<uint8_t> HkdfImpl<Hash>::extract(
    folly::ByteRange salt,
    folly::ByteRange ikm) const {
  auto zeros = std::vector<uint8_t>(Hash::HashLen, 0);
  // Extraction step HMAC-HASH(salt, IKM)
  std::vector<uint8_t> extractedKey(Hash::HashLen);
  salt = salt.empty() ? folly::range(zeros) : salt;
  Hash::hmac(
      salt, folly::IOBuf::wrapBufferAsValue(ikm), folly::range(extractedKey));
  return extractedKey;
}

template <typename Hash>
inline std::unique_ptr<folly::IOBuf> HkdfImpl<Hash>::expand(
    folly::ByteRange extractedKey,
    const folly::IOBuf& info,
    size_t outputBytes) const {
  CHECK_EQ(extractedKey.size(), Hash::HashLen);
  if (UNLIKELY(outputBytes > 255 * Hash::HashLen)) {
    throw std::runtime_error("Output too long");
  }
  // HDKF expansion step.
  size_t numRounds = (outputBytes + Hash::HashLen - 1) / Hash::HashLen;
  if (numRounds > std::numeric_limits<uint8_t>::max()) {
    throw std::runtime_error("Output too long");
  }
  auto expanded = folly::IOBuf::create(numRounds * Hash::HashLen);

  auto in = folly::IOBuf::create(0);
  for (size_t round = 1; round <= numRounds; ++round) {
    in->prependChain(info.clone());
    // We're guaranteed that the round num will fit in
    // one byte because of the check at the beginning of
    // the method.
    auto roundNum = folly::IOBuf::create(1);
    roundNum->append(1);
    roundNum->writableData()[0] = static_cast<uint8_t>(round);
    in->prependChain(std::move(roundNum));

    size_t outputStartIdx = (round - 1) * Hash::HashLen;
    Hash::hmac(
        folly::range(extractedKey),
        *in,
        {expanded->writableData() + outputStartIdx, Hash::HashLen});
    expanded->append(Hash::HashLen);

    in = expanded->clone();
    in->trimStart(outputStartIdx);
  }
  expanded->trimEnd(numRounds * Hash::HashLen - outputBytes);
  return expanded;
}

template <typename Hash>
inline std::unique_ptr<folly::IOBuf> HkdfImpl<Hash>::hkdf(
    folly::ByteRange ikm,
    folly::ByteRange salt,
    const folly::IOBuf& info,
    size_t outputBytes) const {
  return expand(folly::range(extract(salt, ikm)), info, outputBytes);
}
} // namespace fizz
