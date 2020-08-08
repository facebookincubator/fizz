/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/experimental/protocol/BatchSignatureTypes.h>
#include <fizz/experimental/crypto/BatchSignature.h>
#include <fizz/server/AsyncSelfCert.h>

namespace fizz {

/**
 * A decorator class for an exisiting SelfCert/AsyncSelfCert to support both
 * its existing signature schemes and corresponding batch signature schemes.
 */
template <typename Hash = Sha256>
class BatchSignatureAsyncSelfCert : public AsyncSelfCert {
 public:
  /**
   * Construct a batch BatchSignatureAsyncSelfCert instance.
   *
   * @param signer        the existing SelfCert/AsyncSelfCert.
   * @param maxLeavesSize the maximum leaves allowed by the underlying Merkle
   *                      Tree.
   */
  BatchSignatureAsyncSelfCert(
      std::shared_ptr<const SelfCert> signer,
      size_t maxLeavesSize = std::numeric_limits<uint32_t>::max())
      : signer_(signer), maxLeavesSize_(maxLeavesSize) {}

  std::string getIdentity() const override {
    return signer_->getIdentity();
  }

  std::vector<std::string> getAltIdentities() const override {
    return signer_->getAltIdentities();
  }

  fizz::CertificateMsg getCertMessage(
      fizz::Buf certificateRequestContext = nullptr) const override {
    return signer_->getCertMessage(std::move(certificateRequestContext));
  }

  std::vector<SignatureScheme> getSigSchemes() const override {
    auto result = signer_->getSigSchemes();
    auto baseSchemeSize = result.size();
    for (size_t i = 0; i < baseSchemeSize; i++) {
      auto batchScheme =
          BatchSignatureSchemes<Hash>::getFromBaseScheme(result[i]);
      if (batchScheme) {
        result.push_back(*batchScheme);
      }
    }
    return result;
  }

  fizz::CompressedCertificate getCompressedCert(
      fizz::CertificateCompressionAlgorithm algo) const override {
    return signer_->getCompressedCert(algo);
  }

  folly::ssl::X509UniquePtr getX509() const override {
    return signer_->getX509();
  }

  std::unique_ptr<folly::IOBuf> sign(
      fizz::SignatureScheme scheme,
      fizz::CertificateVerifyContext context,
      folly::ByteRange toBeSigned) const override {
    return *signFuture(scheme, context, toBeSigned, nullptr).get();
  }

  folly::Future<folly::Optional<Buf>> signFuture(
      SignatureScheme scheme,
      CertificateVerifyContext context,
      folly::ByteRange message,
      const server::State* state) const override {
    // if is not a batch scheme, use the signer to sign it directly
    auto asyncSigner = dynamic_cast<const AsyncSelfCert*>(signer_.get());
    auto batchSchemeInfo = getBatchSchemeInfo(scheme);
    if (!batchSchemeInfo) {
      if (asyncSigner) {
        return asyncSigner->signFuture(scheme, context, message, state);
      } else {
        return signer_->sign(scheme, context, message);
      }
    }
    // if it is a batch scheme, the scheme must be based on Hash
    const auto& schemes = BatchSignatureSchemes<Hash>::schemes;
    if (std::find(schemes.begin(), schemes.end(), scheme) == schemes.end()) {
      throw std::runtime_error(
          "The specified batch signature's Hash scheme does not match BatchSignatureAsyncSelfCert's Hash scheme.");
    }
    return batchSigSign(
        scheme, batchSchemeInfo.value(), context, message, state);
  }

  /**
   * Get the base SelfCert.
   */
  std::shared_ptr<const SelfCert> getSigner() const {
    return signer_;
  }

 private:
  // TODO: the current implementation uses a batch size of 1 just to test the
  // decorator logic.
  // TODO: the current implementation creates a new Merkle Tree on each
  // batchSigSign function call. In later commits, the Merkle Tree will be
  // managed and assigned separately.
  folly::Future<folly::Optional<Buf>> batchSigSign(
      SignatureScheme scheme,
      BatchSchemeInfo batchInfo,
      CertificateVerifyContext context,
      folly::ByteRange message,
      const server::State* state) const {
    auto tree_ =
        std::make_shared<BatchSignatureMerkleTree<Hash>>(maxLeavesSize_);
    // Add message into the merkle tree and get the root value and path
    auto index = tree_->appendTranscript(message);
    tree_->finalizeAndBuild();
    auto rootValue = tree_->getRootValue();
    auto toBeSigned =
        BatchSignature::encodeToBeSigned(std::move(rootValue), scheme);
    // sign the root value and path with the signer
    auto asyncSigner = dynamic_cast<const AsyncSelfCert*>(signer_.get());
    folly::Future<folly::Optional<Buf>> signature = folly::none;
    if (asyncSigner) {
      signature = asyncSigner->signFuture(
          batchInfo.baseScheme,
          context,
          folly::ByteRange(toBeSigned->data(), toBeSigned->length()),
          state);
    } else {
      signature = signer_->sign(
          batchInfo.baseScheme,
          context,
          folly::ByteRange(toBeSigned->data(), toBeSigned->length()));
    }
    BatchSignature sig(
        tree_->getPath(index.value()), std::move(*signature.value()));
    // encode into the batch signature
    return folly::makeFuture(sig.encode());
  }

  std::shared_ptr<const SelfCert> signer_;
  size_t maxLeavesSize_;
};

} // namespace fizz
