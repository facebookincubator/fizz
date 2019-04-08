/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/tool/FizzCommandCommon.h>
#include <folly/String.h>

using namespace folly;

namespace fizz {
namespace tool {

int parseArguments(
    std::vector<std::string> argv,
    FizzArgHandlerMap handlers,
    std::function<void()> usageFunc) {
  for (size_t idx = 2; idx < argv.size(); idx++) {
    auto& argument = argv[idx];
    auto handlerIter = handlers.find(argument);

    // Ignore these.
    if (argument == "-v" || argument == "-vmodule") {
      idx++;
      continue;
    }

    if (handlerIter != handlers.end()) {
      auto& handlerInfo = handlerIter->second;
      std::string variable;
      if (handlerInfo.hasVariable) {
        if (idx + 1 >= argv.size()) {
          std::cerr << "Argument " << argument << " requires an parameter."
                    << std::endl;
          usageFunc();
          return 1;
        } else {
          idx++;
          variable = argv[idx];
        }
      }
      handlerInfo.handler(variable);
    } else {
      std::cerr << "Unknown argument: " << argument << std::endl;
      usageFunc();
      return 1;
    }
  }
  return 0;
}

TerminalInputHandler::TerminalInputHandler(
    EventBase* evb,
    InputHandlerCallback* cb)
    : EventHandler(evb, folly::NetworkSocket::fromFd(0)), cb_(cb), evb_(evb) {
  registerHandler(EventHandler::READ | EventHandler::PERSIST);
}

void TerminalInputHandler::handlerReady(uint16_t events) noexcept {
  // Handle read ready on stdin, but only once we're connected.
  if (events & EventHandler::READ && cb_->connected()) {
    std::array<char, 512> buf;
    int result = read(0, buf.data(), buf.size());

    if (result > 0) {
      cb_->write(IOBuf::wrapBuffer(buf.data(), result));
    } else {
      if (result < 0) {
        LOG(ERROR) << "Error on terminal read: " << folly::errnoStr(errno);
      }
      hitEOF();
    }
  }
}

void TerminalInputHandler::hitEOF() {
  evb_->runInLoop([cb_ = cb_]() { cb_->close(); });
}

} // namespace tool
} // namespace fizz
