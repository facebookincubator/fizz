/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

namespace fizz {
namespace server {

template <typename ActionMoveVisitor, typename SM>
void FizzServer<ActionMoveVisitor, SM>::accept(
    folly::Executor* executor,
    std::shared_ptr<const FizzServerContext> context,
    std::shared_ptr<ServerExtensions> extensions) {
  checkV2Hello_ = context->getVersionFallbackEnabled();
  this->addProcessingActions(this->machine_.processAccept(
      this->state_, executor, std::move(context), std::move(extensions)));
}

template <typename ActionMoveVisitor, typename SM>
void FizzServer<ActionMoveVisitor, SM>::newTransportData() {
  // If the first data we receive looks like an SSLv2 Client Hello we trigger
  // fallback immediately. This uses the same check as OpenSSL, and OpenSSL
  // does not allow extensions in an SSLv2 Client Hello, so this should not
  // add additional downgrade concerns.
  if (checkV2Hello_) {
    if (!this->actionProcessing() &&
        looksLikeV2ClientHello(this->transportReadBuf_)) {
      VLOG(3) << "Attempting fallback due to V2 ClientHello";
      AttemptVersionFallback fallback;
      fallback.clientHello = this->transportReadBuf_.move();
      return this->addProcessingActions(detail::actions(
          [](State& newState) { newState.state() = StateEnum::Error; },
          std::move(fallback)));
    }
    checkV2Hello_ = false;
  }

  FizzBase<FizzServer<ActionMoveVisitor, SM>, ActionMoveVisitor, SM>::
      newTransportData();
}

template <typename ActionMoveVisitor, typename SM>
Buf FizzServer<ActionMoveVisitor, SM>::getEarlyEkm(
    const Factory& factory,
    folly::StringPiece label,
    const Buf& context,
    uint16_t length) const {
  if (!this->state_.earlyExporterMasterSecret()) {
    throw std::runtime_error("early ekm not available");
  }
  return Exporter::getEkm(
      factory,
      *this->state_.cipher(),
      (*this->state_.earlyExporterMasterSecret())->coalesce(),
      label,
      context ? context->clone() : nullptr,
      length);
}

template <typename ActionMoveVisitor, typename SM>
void FizzServer<ActionMoveVisitor, SM>::startActions(AsyncActions actions) {
  folly::variant_match(
      actions,
      ::fizz::detail::result_type<void>(),
      [this](folly::Future<Actions>& futureActions) {
        std::move(futureActions)
            .then(
                &FizzServer::processActions,
                static_cast<FizzBase<
                    FizzServer<ActionMoveVisitor, SM>,
                    ActionMoveVisitor,
                    SM>*>(this));
      },
      [this](Actions& immediateActions) {
        this->processActions(std::move(immediateActions));
      });
}
} // namespace server
} // namespace fizz
