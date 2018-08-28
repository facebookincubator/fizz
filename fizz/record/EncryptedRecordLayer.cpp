/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/record/EncryptedRecordLayer.h>

namespace fizz {

using ContentTypeType = typename std::underlying_type<ContentType>::type;
using ProtocolVersionType =
    typename std::underlying_type<ProtocolVersion>::type;

static constexpr uint16_t kMaxEncryptedRecordSize = 0x4000 + 256; // 16k + 256
static constexpr size_t kEncryptedHeaderSize =
    sizeof(ContentType) + sizeof(ProtocolVersion) + sizeof(uint16_t);

EncryptedReadRecordLayer::EncryptedReadRecordLayer(
    EncryptionLevel encryptionLevel)
    : encryptionLevel_(encryptionLevel) {}

folly::Optional<Buf> EncryptedReadRecordLayer::getDecryptedBuf(
    folly::IOBufQueue& buf) {
  while (true) {
    folly::io::Cursor cursor(buf.front());

    if (buf.empty() || !cursor.canAdvance(kEncryptedHeaderSize)) {
      return folly::none;
    }

    std::array<uint8_t, kEncryptedHeaderSize> ad;
    folly::io::Cursor adCursor(cursor);
    adCursor.pull(ad.data(), ad.size());
    folly::IOBuf adBuf{folly::IOBuf::wrapBufferAsValue(folly::range(ad))};

    auto contentType =
        static_cast<ContentType>(cursor.readBE<ContentTypeType>());
    cursor.skip(sizeof(ProtocolVersion));

    auto length = cursor.readBE<uint16_t>();
    if (length == 0) {
      throw std::runtime_error("received 0 length encrypted record");
    }
    if (length > kMaxEncryptedRecordSize) {
      throw std::runtime_error("received too long encrypted record");
    }
    if (buf.chainLength() < (cursor - buf.front()) + length) {
      return folly::none;
    }

    if (contentType == ContentType::alert && length == 2) {
      auto alert = decode<Alert>(cursor);
      throw std::runtime_error(folly::to<std::string>(
          "received plaintext alert in encrypted record: ",
          toString(alert.description)));
    }

    std::unique_ptr<folly::IOBuf> encrypted;
    cursor.clone(encrypted, length);
    buf.trimStart(cursor - buf.front());

    if (contentType == ContentType::change_cipher_spec) {
      encrypted->coalesce();
      if (encrypted->length() == 1 && *encrypted->data() == 0x01) {
        continue;
      } else {
        throw FizzException(
            "received ccs", AlertDescription::illegal_parameter);
      }
    }

    TLSMessage msg;
    folly::IOBufQueue decrypted;
    if (seqNum_ == std::numeric_limits<uint64_t>::max()) {
      throw std::runtime_error("max read seq num");
    }
    if (skipFailedDecryption_) {
      auto decryptAttempt = aead_->tryDecrypt(
          std::move(encrypted), useAdditionalData_ ? &adBuf : nullptr, seqNum_);
      if (decryptAttempt) {
        seqNum_++;
        skipFailedDecryption_ = false;
        return decryptAttempt;
      } else {
        continue;
      }
    } else {
      return aead_->decrypt(
          std::move(encrypted),
          useAdditionalData_ ? &adBuf : nullptr,
          seqNum_++);
    }
  }
}

folly::Optional<TLSMessage> EncryptedReadRecordLayer::read(
    folly::IOBufQueue& buf) {
  auto decryptedBuf = getDecryptedBuf(buf);
  if (!decryptedBuf) {
    return folly::none;
  }

  folly::IOBufQueue decrypted;
  decrypted.append(std::move(*decryptedBuf));

  folly::io::Cursor paddingCursor(decrypted.front());
  paddingCursor.advanceToEnd();
  while (!*(paddingCursor -= 1).data()) {
  }
  TLSMessage msg;
  msg.type = static_cast<ContentType>(paddingCursor.readBE<ContentTypeType>());
  decrypted.trimEnd(paddingCursor.totalLength() + sizeof(ContentType));
  msg.fragment = decrypted.move();

  switch (msg.type) {
    case ContentType::handshake:
    case ContentType::alert:
    case ContentType::application_data:
      break;
    default:
      throw std::runtime_error(folly::to<std::string>(
          "received encrypted content type ",
          static_cast<ContentTypeType>(msg.type)));
  }

  if (!msg.fragment) {
    if (msg.type == ContentType::application_data) {
      msg.fragment = folly::IOBuf::create(0);
    } else {
      throw std::runtime_error("received empty fragment");
    }
  }

  return std::move(msg);
}

EncryptionLevel EncryptedReadRecordLayer::getEncryptionLevel() const {
  return encryptionLevel_;
}

EncryptedWriteRecordLayer::EncryptedWriteRecordLayer(
    EncryptionLevel encryptionLevel)
    : encryptionLevel_(encryptionLevel) {}

Buf EncryptedWriteRecordLayer::write(TLSMessage&& msg) const {
  folly::IOBufQueue queue;
  queue.append(std::move(msg.fragment));
  std::unique_ptr<folly::IOBuf> outBuf;
  std::array<uint8_t, kEncryptedHeaderSize> headerBuf;
  auto header = folly::IOBuf::wrapBufferAsValue(folly::range(headerBuf));
  aead_->setEncryptedBufferHeadroom(kEncryptedHeaderSize);
  while (!queue.empty()) {
    auto dataBuf = getBufToEncrypt(queue);
    // Currently we never send padding.

    // check if we have enough room to add the encrypted footer.
    if (!dataBuf->isShared() &&
        dataBuf->prev()->tailroom() >= sizeof(ContentType)) {
      // extend it and add it
      folly::io::Appender appender(dataBuf.get(), 0);
      appender.writeBE(static_cast<ContentTypeType>(msg.type));
    } else {
      // not enough or shared - let's add enough for the tag as well
      auto encryptedFooter = folly::IOBuf::create(
          sizeof(ContentType) + aead_->getCipherOverhead());
      folly::io::Appender appender(encryptedFooter.get(), 0);
      appender.writeBE(static_cast<ContentTypeType>(msg.type));
      dataBuf->prependChain(std::move(encryptedFooter));
    }

    if (seqNum_ == std::numeric_limits<uint64_t>::max()) {
      throw std::runtime_error("max write seq num");
    }

    // we will either be able to memcpy directly into the ciphertext or
    // need to create a new buf to insert before the ciphertext but we need
    // it for additional data
    header.clear();
    folly::io::Appender appender(&header, 0);
    appender.writeBE(
        static_cast<ContentTypeType>(ContentType::application_data));
    appender.writeBE(static_cast<ProtocolVersionType>(recordVersion_));
    auto ciphertextLength =
        dataBuf->computeChainDataLength() + aead_->getCipherOverhead();
    appender.writeBE<uint16_t>(ciphertextLength);

    auto cipherText = aead_->encrypt(
        std::move(dataBuf), useAdditionalData_ ? &header : nullptr, seqNum_++);

    std::unique_ptr<folly::IOBuf> record;
    if (!cipherText->isShared() &&
        cipherText->headroom() >= kEncryptedHeaderSize) {
      // prepend and then write it in
      cipherText->prepend(kEncryptedHeaderSize);
      memcpy(cipherText->writableData(), header.data(), header.length());
      record = std::move(cipherText);
    } else {
      record = folly::IOBuf::copyBuffer(header.data(), header.length());
      record->prependChain(std::move(cipherText));
    }

    if (!outBuf) {
      outBuf = std::move(record);
    } else {
      outBuf->prependChain(std::move(record));
    }
  }

  if (!outBuf) {
    outBuf = folly::IOBuf::create(0);
  }

  return outBuf;
}

EncryptionLevel EncryptedWriteRecordLayer::getEncryptionLevel() const {
  return encryptionLevel_;
}

Buf EncryptedWriteRecordLayer::getBufToEncrypt(folly::IOBufQueue& queue) const {
  static constexpr size_t kMinSuggestedRecordSize = 1500;
  if (queue.front()->length() > maxRecord_) {
    return queue.splitAtMost(maxRecord_);
  } else if (queue.front()->length() >= kMinSuggestedRecordSize) {
    return queue.pop_front();
  } else {
    return queue.splitAtMost(kMinSuggestedRecordSize);
  }
}
} // namespace fizz
