/*
 *  Copyright (c) 2026-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>

#include <fizz/crypto/aead/CryptoUtil.h>

#include <limits>
#include <set>
#include <vector>

namespace fizz {
namespace test {

namespace {

// Independently builds the per-record nonce described by RFC 8446 section 5.3:
// the 64 bit sequence number in big endian, left padded with zeroes to
// ivLength, XORed byte by byte with the traffic IV key.
//
// Requires ivLength >= sizeof(uint64_t); below that the index arithmetic wraps
// and writes out of bounds. expectMatchesReference enforces this.
std::vector<uint8_t> referenceIV(
    uint64_t seqNum,
    size_t ivLength,
    const std::vector<uint8_t>& trafficIvKey) {
  std::vector<uint8_t> iv(ivLength, 0);
  for (size_t i = 0; i < sizeof(uint64_t); ++i) {
    iv[ivLength - 1 - i] = static_cast<uint8_t>(seqNum >> (8 * i));
  }
  for (size_t i = 0; i < ivLength; ++i) {
    iv[i] ^= trafficIvKey[i];
  }
  return iv;
}

std::vector<uint8_t> makeTrafficIvKey(size_t ivLength) {
  std::vector<uint8_t> key(ivLength);
  for (size_t i = 0; i < ivLength; ++i) {
    key[i] = static_cast<uint8_t>(0x40 + i);
  }
  return key;
}

template <size_t kMaxIVLength>
void expectMatchesReference(uint64_t seqNum, size_t ivLength) {
  // createIV writes ivLength bytes into a kMaxIVLength buffer and derives the
  // padding length as ivLength - sizeof(uint64_t), so both bounds must hold
  // for this helper and for referenceIV.
  ASSERT_GE(ivLength, sizeof(uint64_t));
  ASSERT_LE(ivLength, kMaxIVLength);
  const auto key = makeTrafficIvKey(ivLength);
  const auto iv = createIV<kMaxIVLength>(
      seqNum, ivLength, folly::ByteRange(key.data(), key.size()));
  const std::vector<uint8_t> actual(iv.begin(), iv.begin() + ivLength);
  EXPECT_EQ(actual, referenceIV(seqNum, ivLength, key))
      << "seqNum=" << seqNum << " ivLength=" << ivLength;
}

} // namespace

TEST(CryptoUtilTest, CreateIVMatchesReference) {
  // The published TLS 1.3 vectors only ever use sequence numbers 0 and 1,
  // which leave seven of the eight sequence number bytes zero. These also
  // cover byte carries and every byte being set.
  for (const uint64_t seqNum :
       {uint64_t{0},
        uint64_t{1},
        uint64_t{2},
        uint64_t{255},
        uint64_t{256},
        uint64_t{0x0123456789abcdef},
        std::numeric_limits<uint64_t>::max()}) {
    // Smallest permitted IV: the sequence number with no padding at all.
    expectMatchesReference<20>(seqNum, sizeof(uint64_t));
    // AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, via OpenSSLEVPCipher.
    expectMatchesReference<20>(seqNum, 12);
    // Boundary: ivLength equal to the buffer size.
    expectMatchesReference<20>(seqNum, 20);
    // AEGIS-128L and AEGIS-256, via AEGISCipher.
    expectMatchesReference<32>(seqNum, 16);
    expectMatchesReference<32>(seqNum, 32);
  }
}

TEST(CryptoUtilTest, CreateIVIsUniquePerSequenceNumber) {
  // Follows from CreateIVMatchesReference, since XOR with a fixed key is
  // injective. Kept as an explicit statement of the property the construction
  // exists to provide: nonce reuse breaks AEAD confidentiality.
  constexpr size_t kIVLength = 12;
  const auto key = makeTrafficIvKey(kIVLength);
  const folly::ByteRange keyRange(key.data(), key.size());

  std::set<std::vector<uint8_t>> seen;
  for (const uint64_t seqNum :
       {uint64_t{0},
        uint64_t{1},
        uint64_t{2},
        uint64_t{255},
        uint64_t{256},
        uint64_t{0x0123456789abcdef},
        std::numeric_limits<uint64_t>::max()}) {
    const auto iv = createIV<20>(seqNum, kIVLength, keyRange);
    EXPECT_TRUE(seen.emplace(iv.begin(), iv.begin() + kIVLength).second)
        << "duplicate IV for seqNum=" << seqNum;
  }
}

} // namespace test
} // namespace fizz
