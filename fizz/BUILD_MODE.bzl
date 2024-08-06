# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

""" build mode definitions for fizz """

load("@fbcode//:BUILD_MODE.bzl", get_parent_modes = "get_empty_modes")
load("@fbcode//fizz:defs.bzl", "FIZZ_CXX_WARNINGS")
load("@fbcode_macros//build_defs:create_build_mode.bzl", "extend_build_modes")

_extra_cflags = [
]

_common_flags = FIZZ_CXX_WARNINGS

_extra_clang_flags = _common_flags + [
    # Default value for clang (3.4) is 256, change it to GCC's default value
    # (https://fburl.com/23278774).
    "-ftemplate-depth=900",
]

_extra_gcc_flags = _common_flags + [
    "-Wall",
]

_tags = [
]

_modes = extend_build_modes(
    get_parent_modes(),
    c_flags = _extra_cflags,
    clang_flags = _extra_clang_flags,
    cxx_modular_headers = True,
    gcc_flags = _extra_gcc_flags,
    tags = _tags,
)

def get_modes():
    """ Return modes for this file """
    return _modes
