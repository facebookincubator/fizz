/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

namespace fizz {

template <typename Hash>
KeyDerivationImpl<Hash>::KeyDerivationImpl(const std::string& labelPrefix)
    : labelPrefix_(labelPrefix) {}

template <typename Hash>
Buf KeyDerivationImpl<Hash>::expandLabel(
    folly::ByteRange secret,
    folly::StringPiece label,
    Buf hashValue,
    uint16_t length) {
  HkdfLabel hkdfLabel = {
      length, std::string(label.begin(), label.end()), std::move(hashValue)};
  return HkdfImpl<Hash>().expand(
      secret, *encodeHkdfLabel(std::move(hkdfLabel), labelPrefix_), length);
}

template <typename Hash>
Buf KeyDerivationImpl<Hash>::hkdfExpand(
    folly::ByteRange secret,
    Buf info,
    uint16_t length) {
  return HkdfImpl<Hash>().expand(secret, *info, length);
}

template <typename Hash>
std::vector<uint8_t> KeyDerivationImpl<Hash>::deriveSecret(
    folly::ByteRange secret,
    folly::StringPiece label,
    folly::ByteRange messageHash) {
  CHECK_EQ(secret.size(), Hash::HashLen);
  CHECK_EQ(messageHash.size(), Hash::HashLen);
  // Copying the buffer to avoid violating constness of the data.
  auto hashBuf = folly::IOBuf::copyBuffer(messageHash);
  auto out = expandLabel(secret, label, std::move(hashBuf), Hash::HashLen);
  std::vector<uint8_t> prk(Hash::HashLen);
  size_t offset = 0;
  for (auto buf : *out) {
    size_t remaining = Hash::HashLen - offset;
    size_t length = std::min(buf.size(), remaining);
    memcpy(prk.data() + offset, buf.data(), length);
    offset += length;
  }
  return prk;
}
} // namespace fizz
