/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/tool/Commands.h>
#include <folly/ssl/Init.h>
#include <glog/logging.h>

#include <iostream>
#include <string>
#include <vector>

using namespace fizz::tool;

void showUsage() {
  std::cerr << "Supported commands:" << std::endl;
  for (const auto& command : fizzUtilities) {
    std::cerr << "  - " << command.first << std::endl;
  }
  std::cerr << std::endl;
}

int main(int argc, char** argv) {
  google::InitGoogleLogging(argv[0]);
  FLAGS_logtostderr = 1;
  folly::ssl::init();
  std::vector<std::string> arguments;
  for (int i = 0; i < argc; i++) {
    arguments.push_back(argv[i]);
  }

  if (arguments.size() < 2) {
    showUsage();
    return 1;
  } else {
    if (fizzUtilities.count(arguments[1])) {
      return fizzUtilities.at(arguments[1])(arguments);
    } else {
      std::cerr << "Unknown command '" << arguments[1] << "'." << std::endl;
      showUsage();
      return 1;
    }
  }
  return 0;
}
