#include "Hacl.h"

#include "Hacl_AesGCM_NI.h"
#include <fizz/crypto/aead/IOBufUtil.h>
#include <folly/Range.h>
#include <folly/lang/Bits.h>

namespace fizz {
namespace hacl {

std::array<uint8_t, 12> Hacl::createIV(uint64_t seqNum) const {
  std::array<uint8_t, 12> iv;
  uint64_t bigEndianSeqNum = folly::Endian::big(seqNum);
  const size_t prefixLength = 12 - sizeof(uint64_t);
  memset(iv.data(), 0, prefixLength);
  memcpy(iv.data() + prefixLength, &bigEndianSeqNum, 8);
  XOR(key_.iv->coalesce(), folly::range(iv));
  return iv;
}

void Hacl::setKey(TrafficKey tk) {
  tk.key->coalesce();
  tk.iv->coalesce();
  key_ = std::move(tk);
}

std::unique_ptr<folly::IOBuf> Hacl::encrypt(
    std::unique_ptr<folly::IOBuf>&& plaintext,
    const folly::IOBuf* associatedData,
    uint64_t seqNum) const {
  Lib_Vec128_vec128 ctx[22] = {0};
  // get iv and init hacl
  auto iv = createIV(seqNum);
  uint8_t* keyData = const_cast<uint8_t*>(key_.key->data());
  Hacl_AesGCM_NI_aes128_gcm_init(ctx, keyData, iv.data());

  // plaintext needs to be coalesced
  plaintext->coalesce();
  auto inputLen = plaintext->computeChainDataLength();
  // output needs to be one contiguous buffer w/ room for the tag
  auto out = folly::IOBuf::create(headroom_ + inputLen + getCipherOverhead());
  out->advance(headroom_);
  out->append(inputLen + getCipherOverhead());
  auto inData = const_cast<uint8_t*>(plaintext->data());

  // set up aad
  uint8_t* aad = nullptr;
  size_t aadLen = 0;
  if (associatedData) {
    auto adbuf = const_cast<folly::IOBuf*>(associatedData);
    adbuf->coalesce();
    aad = const_cast<uint8_t*>(adbuf->data());
    aadLen = adbuf->computeChainDataLength();
  }

  // hacl encrypt!
  Hacl_AesGCM_NI_aes128_gcm_encrypt(
      ctx, inputLen, out->writableData(), inData, aadLen, aad);

  // assume it worked?
  return out;
}

folly::Optional<std::unique_ptr<folly::IOBuf>> Hacl::tryDecrypt(
    std::unique_ptr<folly::IOBuf>&& ciphertext,
    const folly::IOBuf* associatedData,
    uint64_t seqNum) const {
  Lib_Vec128_vec128 ctx[22] = {0};
  // set up
  // get iv and init hacl
  auto iv = createIV(seqNum);
  uint8_t* keyData = const_cast<uint8_t*>(key_.key->data());
  Hacl_AesGCM_NI_aes128_gcm_init(ctx, keyData, iv.data());

  // set up aad
  uint8_t* aad = nullptr;
  size_t aadLen = 0;
  if (associatedData) {
    auto adbuf = const_cast<folly::IOBuf*>(associatedData);
    adbuf->coalesce();
    aad = const_cast<uint8_t*>(adbuf->data());
    aadLen = adbuf->computeChainDataLength();
  }

  ciphertext->coalesce();
  auto inputLen = ciphertext->computeChainDataLength();
  if (inputLen <= getCipherOverhead()) {
    return folly::none;
  }
  auto out = folly::IOBuf::create(inputLen - getCipherOverhead());
  out->append(inputLen - getCipherOverhead());

  auto cipherData = const_cast<uint8_t*>(ciphertext->data());

  auto res = Hacl_AesGCM_NI_aes128_gcm_decrypt(
      ctx, inputLen-16, out->writableData(), cipherData, aadLen, aad);

  if (!res) {
    return folly::none;
  }
  return out;
}

} // namespace hacl
} // namespace fizz
