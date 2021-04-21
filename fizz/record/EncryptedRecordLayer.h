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

  explicit EncryptedReadRecordLayer(EncryptionLevel encryptionLevel)
      : encryptionLevel_(encryptionLevel) {}

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

  void setSequenceNumber(uint64_t seq) {
    seqNum_ = seq;
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

  RecordLayerState getRecordLayerState() const override {
    auto key = [&]() -> folly::Optional<TrafficKey> {
      if (!aead_) {
        return folly::none;
      }
      return aead_->getKey();
    }();

    auto sequence = seqNum_;

    return RecordLayerState{std::move(key), sequence};
  }

 private:
  folly::Optional<Buf> getDecryptedBuf(folly::IOBufQueue& buf);

  EncryptionLevel encryptionLevel_;
  std::unique_ptr<Aead> aead_;
  mutable uint64_t seqNum_{0};

  bool skipFailedDecryption_{false};
  bool useAdditionalData_{true};
};

class EncryptedWriteRecordLayer : public WriteRecordLayer {
 public:
  ~EncryptedWriteRecordLayer() override = default;

  explicit EncryptedWriteRecordLayer(EncryptionLevel encryptionLevel)
      : encryptionLevel_(encryptionLevel) {}

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
    DCHECK_GE(maxRecord_, desiredMinRecord_);
    maxRecord_ = size;
  }

  void setMinDesiredRecord(uint16_t size) {
    CHECK_GT(size, 0);
    DCHECK_LE(size, kMaxPlaintextRecordSize);
    DCHECK_LE(desiredMinRecord_, maxRecord_);
    desiredMinRecord_ = size;
  }

  void setSequenceNumber(uint64_t seq) {
    seqNum_ = seq;
  }

  EncryptionLevel getEncryptionLevel() const override;

  RecordLayerState getRecordLayerState() const override {
    auto key = [&]() -> folly::Optional<TrafficKey> {
      if (!aead_) {
        return folly::none;
      }
      return aead_->getKey();
    }();

    auto sequence = seqNum_;

    return RecordLayerState{std::move(key), sequence};
  }

 private:
  Buf getBufToEncrypt(folly::IOBufQueue& queue) const;

  EncryptionLevel encryptionLevel_;
  std::unique_ptr<Aead> aead_;
  mutable uint64_t seqNum_{0};

  uint16_t maxRecord_{kMaxPlaintextRecordSize};
  uint16_t desiredMinRecord_{kMinSuggestedRecordSize};
};
} // namespace fizz
