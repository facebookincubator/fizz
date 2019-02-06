/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/record/RecordLayer.h>

#include <fizz/crypto/aead/Aead.h>

namespace fizz {

constexpr uint16_t kMaxPlaintextRecordSize = 0x4000; // 16k
constexpr uint16_t kMinSuggestedRecordSize = 1500;

class EncryptedReadRecordLayer : public ReadRecordLayer {
 public:
  ~EncryptedReadRecordLayer() override = default;

  explicit EncryptedReadRecordLayer(EncryptionLevel encryptionLevel);

  folly::Optional<TLSMessage> read(folly::IOBufQueue& buf) override;

  virtual void setAead(
      folly::ByteRange /* baseSecret */,
      std::unique_ptr<Aead> aead) {
    if (seqNum_ != 0) {
      throw std::runtime_error("aead set after read");
    }
    aead_ = std::move(aead);
  }

  virtual void setSkipFailedDecryption(bool enabled) {
    skipFailedDecryption_ = enabled;
  }

  void setProtocolVersion(ProtocolVersion version) {
    auto realVersion = getRealDraftVersion(version);
    if (realVersion == ProtocolVersion::tls_1_3_23) {
      useAdditionalData_ = false;
    } else {
      useAdditionalData_ = true;
    }
  }

  EncryptionLevel getEncryptionLevel() const override;

 private:
  folly::Optional<Buf> getDecryptedBuf(folly::IOBufQueue& buf);

  EncryptionLevel encryptionLevel_;
  std::unique_ptr<Aead> aead_;
  bool skipFailedDecryption_{false};

  bool useAdditionalData_{true};

  mutable uint64_t seqNum_{0};
};

class EncryptedWriteRecordLayer : public WriteRecordLayer {
 public:
  ~EncryptedWriteRecordLayer() override = default;

  explicit EncryptedWriteRecordLayer(EncryptionLevel encryptionLevel);

  TLSContent write(TLSMessage&& msg) const override;

  virtual void setAead(
      folly::ByteRange /* baseSecret */,
      std::unique_ptr<Aead> aead) {
    if (seqNum_ != 0) {
      throw std::runtime_error("aead set after write");
    }
    aead_ = std::move(aead);
  }

  void setMaxRecord(uint16_t size) {
    CHECK_GT(size, 0);
    DCHECK_LE(size, kMaxPlaintextRecordSize);
    maxRecord_ = size;
  }

  void setMinDesiredRecord(uint16_t size) {
    CHECK_GT(size, 0);
    DCHECK_LE(size, kMaxPlaintextRecordSize);
    desiredMinRecord_ = size;
  }

  EncryptionLevel getEncryptionLevel() const override;

 private:
  Buf getBufToEncrypt(folly::IOBufQueue& queue) const;

  std::unique_ptr<Aead> aead_;

  uint16_t maxRecord_{kMaxPlaintextRecordSize};
  uint16_t desiredMinRecord_{kMinSuggestedRecordSize};

  mutable uint64_t seqNum_{0};
  EncryptionLevel encryptionLevel_;
};
} // namespace fizz
