/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Memory.h>
#include <folly/String.h>
#include <folly/io/IOBuf.h>

namespace fizz {
namespace test {

// Converts the hex encoded string to an IOBuf.
std::unique_ptr<folly::IOBuf> toIOBuf(std::string hexData);

std::unique_ptr<folly::IOBuf> chunkIOBuf(
    std::unique_ptr<folly::IOBuf> input,
    size_t chunks);
} // namespace test
} // namespace fizz
