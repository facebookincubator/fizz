/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/experimental/batcher/Batcher.h>
#include <fizz/crypto/test/TestUtil.h>
#include <fizz/experimental/client/BatchSignaturePeerCert.h>
#include <fizz/experimental/server/BatchSignatureAsyncSelfCert.h>
#include <fizz/server/State.h>
#include <fizz/server/test/Mocks.h>
#include <folly/portability/GTest.h>

namespace fizz {
namespace test {

TEST(BatchSignatureTest, TestWhenSignerIsAsync) {
  // the future returned by addMessageAndSign() will be fulfilled when the
  // signature future returned by the async signer is fulfilled.
  auto mockBaseCert = std::make_shared<server::test::MockAsyncSelfCert>();
  auto batcher = std::make_shared<SynchronizedBatcher<Sha256>>(
      1, mockBaseCert, CertificateVerifyContext::Server);
  auto [promise, semiFuture] = folly::makePromiseContract<folly::Optional<Buf>>();
  auto future = std::move(semiFuture).toUnsafeFuture();
  EXPECT_CALL(*mockBaseCert, signFuture(_, _, _, _))
      .Times(1)
      .WillOnce(InvokeWithoutArgs([&]() { return std::move(future); }));
  auto futureTree =
      batcher->addMessageAndSign(folly::range(folly::StringPiece("Message1")));
  EXPECT_FALSE(futureTree.future_.isReady());
  promise.setValue(folly::IOBuf::copyBuffer("mockSignature"));
  EXPECT_TRUE(futureTree.future_.isReady());
}

TEST(BatchSignatureTest, TestWhenSignerFails) {
  // the future returned by addMessageAndSign() will throw an error when
  // underlying signer returns a none signature.
  auto mockBaseCert = std::make_shared<server::test::MockAsyncSelfCert>();
  auto batcher = std::make_shared<SynchronizedBatcher<Sha256>>(
      1, mockBaseCert, CertificateVerifyContext::Server);
  EXPECT_CALL(*mockBaseCert, signFuture(_, _, _, _))
      .Times(1)
      .WillOnce(InvokeWithoutArgs([]() { return folly::none; }));
  auto futureTree =
      batcher->addMessageAndSign(folly::range(folly::StringPiece("Message1")));
  EXPECT_TRUE(futureTree.future_.isReady());
  EXPECT_THROW(std::move(futureTree.future_).get(), std::runtime_error);
}

TEST(BatchSignatureTest, TestSynchronizedBatcherSingleThread) {
  useMockRandom();
  std::vector<folly::ssl::X509UniquePtr> certs;
  certs.emplace_back(getCert(kRSACertificate));
  auto certificate = std::make_shared<SelfCertImpl<KeyType::RSA>>(
      getPrivateKey(kRSAKey), std::move(certs));

  auto batcher = std::make_shared<SynchronizedBatcher<Sha256>>(
      3, certificate, CertificateVerifyContext::Server);
  auto futureTree1 =
      batcher->addMessageAndSign(folly::range(folly::StringPiece("Message1")));
  EXPECT_FALSE(futureTree1.future_.isReady());
  auto futureTree2 =
      batcher->addMessageAndSign(folly::range(folly::StringPiece("Message2")));
  EXPECT_FALSE(futureTree2.future_.isReady());
  auto futureTree3 =
      batcher->addMessageAndSign(folly::range(folly::StringPiece("Message3")));
  EXPECT_TRUE(futureTree3.future_.isReady());
  auto tree1 = std::move(futureTree1.future_).get();
  auto tree2 = std::move(futureTree2.future_).get();
  auto tree3 = std::move(futureTree3.future_).get();
  auto root1 = tree1.tree_->getRootValue()->moveToFbString();
  auto root2 = tree2.tree_->getRootValue()->moveToFbString();
  auto root3 = tree3.tree_->getRootValue()->moveToFbString();
  EXPECT_EQ(root1, root2);
  EXPECT_EQ(root1, root3);
  EXPECT_EQ(
      folly::hexlify(root1.toStdString()),
      "6d744da84b3f23c9a224c8e9a5919b432992223b9cc77515f5dc07b83c62c021");
}

TEST(BatchSignatureTest, TestSynchronizedBatcherMultiThread) {
  useMockRandom();

  size_t numMsgThreshold = 3;
  std::vector<folly::ssl::X509UniquePtr> certs;
  certs.emplace_back(getCert(kRSACertificate));
  auto certificate = std::make_shared<SelfCertImpl<KeyType::RSA>>(
      getPrivateKey(kRSAKey), std::move(certs));

  auto batcher = std::make_shared<SynchronizedBatcher<Sha256>>(
      numMsgThreshold, certificate, CertificateVerifyContext::Server);
  std::vector<std::thread> threads;
  std::vector<folly::fbstring> results;
  results.resize(numMsgThreshold);
  for (size_t i = 0; i < numMsgThreshold; i++) {
    auto& result = results[i];
    threads.emplace_back(std::thread([=, &result]() {
      auto futureTree = batcher->addMessageAndSign(
          folly::range(folly::StringPiece("Message")));
      auto signedTree = std::move(futureTree.future_).get();
      auto rootValue = signedTree.tree_->getRootValue();
      result = rootValue->moveToFbString();
    }));
  }
  for (auto& t : threads) {
    t.join();
  }
  for (size_t i = 1; i < numMsgThreshold; i++) {
    EXPECT_EQ(results[i], results[i - 1]);
  }
  EXPECT_EQ(
      folly::hexlify(results[0].toStdString()),
      "aef99bf71711b3dbec0afab0a95cb40e559eaaf76bc70a1ae0be36b6ce8aa818");
}

TEST(BatchSignatureTest, TestSynchronizedBatcherWithSelfCertP256) {
  size_t numMsgThreshold = 3;
  std::vector<folly::ssl::X509UniquePtr> certs;
  certs.emplace_back(getCert(kP256Certificate));
  auto certificate = std::make_shared<SelfCertImpl<KeyType::P256>>(
      getPrivateKey(kP256Key), std::move(certs));
  auto batcher = std::make_shared<SynchronizedBatcher<Sha256>>(
      numMsgThreshold, certificate, CertificateVerifyContext::Server);

  std::vector<std::thread> threads;
  std::vector<folly::fbstring> results;
  results.resize(numMsgThreshold * 10);
  for (size_t i = 0; i < numMsgThreshold * 10; i++) {
    auto batchCert =
        std::make_shared<BatchSignatureAsyncSelfCert<Sha256>>(batcher);
    auto& result = results[i];
    // create thread to generate signature
    threads.emplace_back(std::thread([=, &result]() {
      auto signature =
          std::dynamic_pointer_cast<AsyncSelfCert>(batchCert)->signFuture(
              SignatureScheme::ecdsa_secp256r1_sha256_batch,
              CertificateVerifyContext::Server,
              folly::range(folly::StringPiece("Message" + std::to_string(i))),
              nullptr);
      result = (*std::move(signature).get())->moveToFbString();
    }));
  }
  for (auto& t : threads) {
    t.join();
  }

  // verify
  auto peerCert =
      std::make_shared<PeerCertImpl<KeyType::P256>>(getCert(kP256Certificate));
  BatchSignaturePeerCert batchPeerCert(peerCert);
  for (size_t i = 0; i < results.size(); i++) {
    batchPeerCert.verify(
        SignatureScheme::ecdsa_secp256r1_sha256_batch,
        CertificateVerifyContext::Server,
        folly::range(folly::StringPiece("Message" + std::to_string(i))),
        folly::range(results[i]));
  }
}

} // namespace test
} // namespace fizz
