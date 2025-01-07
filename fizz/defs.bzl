load("@fbcode_macros//build_defs:cpp_library.bzl", "cpp_library")
load("@fbsource//tools/build_defs:buckconfig.bzl", "read", "read_bool")
load("@fbsource//tools/build_defs:cell_defs.bzl", "get_fbsource_cell")
load("@fbsource//tools/build_defs:fb_xplat_cxx_binary.bzl", "fb_xplat_cxx_binary")
load("@fbsource//tools/build_defs:fb_xplat_cxx_library.bzl", "fb_xplat_cxx_library")
load("@fbsource//tools/build_defs:fb_xplat_cxx_test.bzl", "fb_xplat_cxx_test")
load(
    "@fbsource//tools/build_defs:platform_defs.bzl",
    "ANDROID",
    "APPLE",
    "CXX",
    "FBCODE",
    "IOS",
    "MACOSX",
    "WINDOWS",
)

# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
load("@fbsource//tools/build_defs/xplat:deps_map_utils.bzl", "deps_map_utils")
load("@fbsource//xplat/pfh/Infra_Networking_Core:DEFS.bzl", "Infra_Networking_Core")

# Fizz is a cross platform library used across fbcode, fbobjc, fbandroid, etc.
#
# Each build environment defines a separate set of default warning flags.
# Since we primarily develop within fbcode, this meant that we would see our
# builds pass on our devserver, then fail a sandcastle xplat contbuild job at
# difftime (or worse, some contbuilds are asynchronous so we only find out
# about this after land) since some of these environments define `-Werror`.
#
FIZZ_EXTRA_CXX_WARNINGS = [
    # Apple builds warn against this, but Fizz requires static initializers
    # so we *need* global-constructors.
    "-Wno-error=global-constructors",
    "-Werror=mismatched-tags",
    "-Werror=shadow",
    "-Werror=sign-compare",
    "-Werror=unused-exception-parameter",
    "-Werror=constant-conversion",
]

FIZZ_CXX_WARNINGS = [
    "-Wno-error",
    "-Werror=comment",
    "-Werror=format",
    "-Werror=format-security",
    "-Werror=missing-braces",
    "-Werror=return-type",
    "-Werror=uninitialized",
    "-Werror=unused-function",
    "-Werror=unused-local-typedefs",
    "-Werror=unused-variable",
] + FIZZ_EXTRA_CXX_WARNINGS if ("oe-linux-gcc9" not in read("toolchain", "PROG", "")) else []

CXXFLAGS = [
    "-frtti",
    "-fexceptions",
    "-fstack-protector-strong",
] + FIZZ_CXX_WARNINGS

FBANDROID_CXXFLAGS = [
    "-ffunction-sections",
    "-fstack-protector-strong",
]

FBOBJC_CXXFLAGS = [
    "-fstack-protector-strong",
]

WINDOWS_MSVC_CXXFLAGS = [
    "/EHs",
]

WINDOWS_CLANG_CXX_FLAGS_NO_SSE4 = [
    "-Wno-deprecated-declarations",
    "-Wno-microsoft-cast",
    "-DBOOST_HAS_THREADS",
]

WINDOWS_CLANG_CXX_FLAGS = WINDOWS_CLANG_CXX_FLAGS_NO_SSE4 + [
    "-msse4.2",
]

DEFAULT_APPLE_SDKS = (IOS, MACOSX)
DEFAULT_PLATFORMS = (ANDROID, APPLE, CXX, FBCODE, WINDOWS)

def _compute_include_directories():
    base_path = native.package_name()
    if base_path == "xplat/fizz":
        return [".."]
    fizz_path = base_path[6:]
    return ["/".join(len(fizz_path.split("/")) * [".."])]

def _compute_header_namespace():
    base_path = native.package_name()
    return base_path[6:]

def fizz_cpp_library(
        name,
        headers = [],
        private_headers = [],
        srcs = [],
        deps = None,
        exported_deps = None,
        external_deps = None,
        exported_external_deps = None,
        **kwargs):
    """Translate a simpler declartion into the more complete library target"""
    if get_fbsource_cell() == "fbcode":
        cpp_library(
            name = name,
            headers = headers,
            private_headers = private_headers,
            srcs = srcs,
            deps = deps,
            exported_deps = exported_deps,
            external_deps = external_deps,
            exported_external_deps = exported_external_deps,
        )
    else:
        converted_deps = deps_map_utils.convert_all_to_fbsource_deps(
            deps = deps,
            exported_deps = exported_deps,
            external_deps = external_deps,
            exported_external_deps = exported_external_deps,
        )
        fizz_cxx_library(
            name = name,
            exported_headers = headers,
            headers = private_headers,
            srcs = srcs,
            deps = converted_deps.deps,
            exported_deps = converted_deps.exported_deps,
            **kwargs
        )

def fizz_cxx_library(
        name,
        platforms = None,
        apple_sdks = None,
        headers = [],
        exported_headers = [],
        enable_static_variant = True,
        header_namespace = "",
        feature = None,
        srcs = [],
        **kwargs):
    """Translate a simpler declartion into the more complete library target"""
    if apple_sdks == None:
        apple_sdks = DEFAULT_APPLE_SDKS
    if platforms == None:
        platforms = DEFAULT_PLATFORMS
    if feature == None:
        feature = Infra_Networking_Core

    windows_compiler_flags = WINDOWS_CLANG_CXX_FLAGS if read_bool("fizz", "enable_sse4", True) else WINDOWS_CLANG_CXX_FLAGS_NO_SSE4

    if headers or exported_headers:
        public_include_directories = []
        header_namespace = _compute_header_namespace()
    else:
        public_include_directories = _compute_include_directories()
        header_namespace = ""

    fb_xplat_cxx_library(
        name = name,
        srcs = native.glob(srcs) if srcs else [],
        feature = feature,
        enable_static_variant = enable_static_variant,
        platforms = platforms,
        apple_sdks = apple_sdks,
        headers = headers,
        exported_headers = exported_headers,
        header_namespace = header_namespace,
        public_include_directories = public_include_directories,
        compiler_flags = kwargs.pop("compiler_flags", []) + CXXFLAGS,
        windows_compiler_flags = kwargs.pop("windows_compiler_flags", []) + windows_compiler_flags,
        fbobjc_compiler_flags = kwargs.pop("fbobjc_compiler_flags", []) + FBOBJC_CXXFLAGS,
        fbobjc_exported_preprocessor_flags = kwargs.pop("fbobjc_exported_preprocessor_flags", []),
        fbandroid_compiler_flags = kwargs.pop("fbandroid_compiler_flags", []) + FBANDROID_CXXFLAGS,
        windows_msvc_compiler_flags_override = kwargs.pop("windows_msvc_compiler_flags_override", WINDOWS_MSVC_CXXFLAGS),
        visibility = kwargs.pop("visibility", ["PUBLIC"]),
        **kwargs
    )

def fizz_cxx_binary(name, **kwargs):
    fb_xplat_cxx_binary(
        name = name,
        platforms = (CXX,),
        contacts = ["oncall+secure_pipes@xmail.facebook.com"],
        **kwargs
    )

def fizz_cxx_test(name, **kwargs):
    fb_xplat_cxx_test(
        name = name,
        platforms = (CXX,),
        contacts = ["oncall+secure_pipes@xmail.facebook.com"],
        **kwargs
    )
