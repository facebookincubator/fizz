/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/util/Parse.h>
#include <folly/io/IOBuf.h>
#include <folly/io/async/EventBase.h>
#include <folly/io/async/EventHandler.h>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace fizz {
namespace tool {

inline uint16_t portFromString(const std::string& portStr, bool serverSide) {
  unsigned long converted = 0;
  try {
    converted = std::stoul(portStr);
  } catch (const std::exception&) {
    throw std::runtime_error(
        "Couldn't convert " + portStr + " to port number.");
  }
  if (converted <= std::numeric_limits<uint16_t>::max()) {
    if (converted == 0 && !serverSide) {
      throw std::runtime_error("Port 0 is not valid for client ports.");
    }
    return static_cast<uint16_t>(converted);
  } else {
    throw std::runtime_error(
        "Couldn't convert " + portStr + " to port number.");
  }
}

// Argument handler function

typedef std::function<void(const std::string&)> FizzCommandArgHandler;
struct FizzCommandArgHandlerInfo {
  bool hasVariable;
  FizzCommandArgHandler handler;
};
typedef std::map<std::string, FizzCommandArgHandlerInfo> FizzArgHandlerMap;

int parseArguments(
    std::vector<std::string> argv,
    FizzArgHandlerMap handlers,
    std::function<void()> usageFunc);

// Utility to convert from comma-separated string to vector of T that has
// a parse() implementation in util/Parse.h
template <typename T>
inline std::vector<T> fromCSV(const std::string& arg) {
  std::vector<folly::StringPiece> pieces;
  std::vector<T> output;
  folly::split(",", arg, pieces);
  std::transform(
      pieces.begin(), pieces.end(), std::back_inserter(output), parse<T>);
  return output;
}

// Echo client/server classes

class InputHandlerCallback {
 public:
  virtual ~InputHandlerCallback() = default;
  virtual void write(std::unique_ptr<folly::IOBuf> msg) = 0;
  virtual void close() = 0;
  virtual bool connected() const = 0;
};

class TerminalInputHandler : public folly::EventHandler {
 public:
  explicit TerminalInputHandler(
      folly::EventBase* evb,
      InputHandlerCallback* cb);
  void handlerReady(uint16_t events) noexcept override;

 private:
  void hitEOF();

  InputHandlerCallback* cb_;
  folly::EventBase* evb_;
};

} // namespace tool
} // namespace fizz
