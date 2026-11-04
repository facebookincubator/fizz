/*
 *  Copyright (c) Meta Platforms, Inc. and affiliates.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/util/Status.h>

#include <cstddef>

namespace fizz {

/**
 * Fills `out` with `count` cryptographically secure random bytes.
 */
Status random(Error& err, unsigned char* out, size_t count);

namespace detail {
// For tests only: makes `random()` fill its output with `fn`; null restores it.
void setRandomForTesting(void (*fn)(unsigned char* out, size_t count));
} // namespace detail

} // namespace fizz
