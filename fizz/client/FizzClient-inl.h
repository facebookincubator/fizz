/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

namespace fizz {
namespace client {

template <typename ActionMoveVisitor, typename SM>
void FizzClient<ActionMoveVisitor, SM>::connect(
    std::shared_ptr<const FizzClientContext> context,
    std::shared_ptr<const CertificateVerifier> verifier,
    folly::Optional<std::string> sni,
    folly::Optional<CachedPsk> cachedPsk,
    const std::shared_ptr<ClientExtensions>& extensions) {
  this->addProcessingActions(this->machine_.processConnect(
      this->state_,
      std::move(context),
      std::move(verifier),
      std::move(sni),
      std::move(cachedPsk),
      extensions));
}

template <typename ActionMoveVisitor, typename SM>
void FizzClient<ActionMoveVisitor, SM>::connect(
    std::shared_ptr<const FizzClientContext> context,
    folly::Optional<std::string> hostname) {
  const auto pskIdentity = hostname;
  connect(
      std::move(context),
      std::make_shared<DefaultCertificateVerifier>(VerificationContext::Client),
      std::move(hostname),
      std::move(pskIdentity));
}

template <typename ActionMoveVisitor, typename SM>
Buf FizzClient<ActionMoveVisitor, SM>::getEarlyEkm(
    const Factory& factory,
    folly::StringPiece label,
    const Buf& context,
    uint16_t length) const {
  if (!this->state_.earlyDataParams()) {
    throw std::runtime_error("early ekm not available");
  }
  return Exporter::getEkm(
      factory,
      this->state_.earlyDataParams()->cipher,
      this->state_.earlyDataParams()->earlyExporterSecret->coalesce(),
      label,
      context ? context->clone() : nullptr,
      length);
}

template <typename ActionMoveVisitor, typename SM>
void FizzClient<ActionMoveVisitor, SM>::startActions(Actions actions) {
  this->processActions(std::move(actions));
}
} // namespace client
} // namespace fizz
