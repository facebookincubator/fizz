/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/protocol/Exporter.h>
#include <fizz/util/Workarounds.h>

namespace fizz {
template <typename Derived, typename ActionMoveVisitor, typename StateMachine>
void FizzBase<Derived, ActionMoveVisitor, StateMachine>::writeNewSessionTicket(
    WriteNewSessionTicket w) {
  pendingEvents_.push_back(std::move(w));
  processPendingEvents();
}

template <typename Derived, typename ActionMoveVisitor, typename StateMachine>
void FizzBase<Derived, ActionMoveVisitor, StateMachine>::appWrite(AppWrite w) {
  pendingEvents_.push_back(std::move(w));
  processPendingEvents();
}

template <typename Derived, typename ActionMoveVisitor, typename StateMachine>
void FizzBase<Derived, ActionMoveVisitor, StateMachine>::earlyAppWrite(
    EarlyAppWrite w) {
  pendingEvents_.push_back(std::move(w));
  processPendingEvents();
}

template <typename Derived, typename ActionMoveVisitor, typename StateMachine>
void FizzBase<Derived, ActionMoveVisitor, StateMachine>::appClose() {
  pendingEvents_.push_back(AppClose::WAIT);
  processPendingEvents();
}

template <typename Derived, typename ActionMoveVisitor, typename StateMachine>
void FizzBase<Derived, ActionMoveVisitor, StateMachine>::appCloseImmediate() {
  pendingEvents_.push_back(AppClose::IMMEDIATE);
  processPendingEvents();
}

template <typename Derived, typename ActionMoveVisitor, typename StateMachine>
void FizzBase<Derived, ActionMoveVisitor, StateMachine>::waitForData() {
  waitForData_ = true;
}

template <typename Derived, typename ActionMoveVisitor, typename StateMachine>
void FizzBase<Derived, ActionMoveVisitor, StateMachine>::newTransportData() {
  waitForData_ = false;
  processPendingEvents();
}

template <typename Derived, typename ActionMoveVisitor, typename StateMachine>
void FizzBase<Derived, ActionMoveVisitor, StateMachine>::moveToErrorState(
    const folly::AsyncSocketException& ex) {
  // We use a separate flag here rather than just moving the state to Error
  // since there may be a currently processing action.
  externalError_ = true;
  while (!pendingEvents_.empty()) {
    auto event = std::move(pendingEvents_.front());
    pendingEvents_.pop_front();
    folly::variant_match(
        event,
        detail::result_type<void>(),
        [&ex](AppWrite& write) {
          if (write.callback) {
            write.callback->writeErr(0, ex);
          }
        },
        [&ex](EarlyAppWrite& write) {
          if (write.callback) {
            write.callback->writeErr(0, ex);
          }
        },
        [](auto&) {});
  }
}

template <typename Derived, typename ActionMoveVisitor, typename StateMachine>
bool FizzBase<Derived, ActionMoveVisitor, StateMachine>::inErrorState() const {
  return state_.state() == decltype(state_.state())::Error;
}

template <typename Derived, typename ActionMoveVisitor, typename StateMachine>
bool FizzBase<Derived, ActionMoveVisitor, StateMachine>::inTerminalState()
    const {
  return inErrorState() || externalError_ ||
      state_.state() == decltype(state_.state())::Closed;
}

template <typename Derived, typename ActionMoveVisitor, typename StateMachine>
bool FizzBase<Derived, ActionMoveVisitor, StateMachine>::actionProcessing()
    const {
  return actionGuard_.hasValue();
}

template <typename Derived, typename ActionMoveVisitor, typename StateMachine>
void FizzBase<Derived, ActionMoveVisitor, StateMachine>::processActions(
    typename StateMachine::CompletedActions actions) {
  // This extra DestructorGuard is needed due to the gap between clearing
  // actionGuard_ and potentially processing another action.
  folly::DelayedDestruction::DestructorGuard dg(owner_);

  for (auto& action : actions) {
    boost::apply_visitor(visitor_, action);
  }

  actionGuard_.clear();
  processPendingEvents();
}

template <typename Derived, typename ActionMoveVisitor, typename StateMachine>
void FizzBase<Derived, ActionMoveVisitor, StateMachine>::addProcessingActions(
    typename StateMachine::ProcessingActions actions) {
  if (actionGuard_) {
    throw std::runtime_error("actions already processing");
  }

  actionGuard_ = folly::DelayedDestruction::DestructorGuard(owner_);

  static_cast<Derived*>(this)->startActions(std::move(actions));
}

template <typename Derived, typename ActionMoveVisitor, typename StateMachine>
void FizzBase<Derived, ActionMoveVisitor, StateMachine>::
    processPendingEvents() {
  if (inProcessPendingEvents_) {
    return;
  }

  folly::DelayedDestruction::DestructorGuard dg(owner_);
  inProcessPendingEvents_ = true;
  SCOPE_EXIT {
    inProcessPendingEvents_ = false;
  };

  while (!actionGuard_ && !inTerminalState()) {
    folly::Optional<typename StateMachine::ProcessingActions> actions;
    actionGuard_ = folly::DelayedDestruction::DestructorGuard(owner_);
    if (!waitForData_) {
      actions = machine_.processSocketData(state_, transportReadBuf_);
    } else if (!pendingEvents_.empty()) {
      auto event = std::move(pendingEvents_.front());
      pendingEvents_.pop_front();
      folly::variant_match(
          event,
          detail::result_type<void>(),
          [&actions, this](WriteNewSessionTicket& write) {
            actions =
                machine_.processWriteNewSessionTicket(state_, std::move(write));
          },
          [&actions, this](AppWrite& write) {
            actions = machine_.processAppWrite(state_, std::move(write));
          },
          [&actions, this](EarlyAppWrite& write) {
            actions = machine_.processEarlyAppWrite(state_, std::move(write));
          },
          [&actions, this](AppClose& close) {
            if (close.policy == AppClose::WAIT) {
              actions = machine_.processAppClose(state_);
            } else {
              actions = machine_.processAppCloseImmediate(state_);
            }
          });
    } else {
      actionGuard_.clear();
      return;
    }

    static_cast<Derived*>(this)->startActions(std::move(*actions));
  }
}

template <typename Derived, typename ActionMoveVisitor, typename StateMachine>
Buf FizzBase<Derived, ActionMoveVisitor, StateMachine>::getEkm(
    const Factory& factory,
    folly::StringPiece label,
    const Buf& context,
    uint16_t length) const {
  return Exporter::getEkm(
      factory,
      *state_.cipher(),
      (*state_.exporterMasterSecret())->coalesce(),
      label,
      context ? context->clone() : nullptr,
      length);
}
} // namespace fizz
