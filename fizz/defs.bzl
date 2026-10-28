# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

load("@fbsource//tools/build_defs:fb_xplat_cxx_binary.bzl", "fb_xplat_cxx_binary")
load("@fbsource//tools/build_defs:fb_xplat_cxx_library.bzl", "fb_xplat_cxx_library")
load("@fbsource//tools/build_defs:fb_xplat_cxx_test.bzl", "fb_xplat_cxx_test")
load(
    "@fbsource//tools/build_defs:platform_defs.bzl",
    "ANDROID",
    "APPLE",
    "APPLETVOS",
    "CXX",
    "FBCODE",
    "IOS",
    "MACOSX",
    "WINDOWS",
)
load("@fbsource//tools/build_defs/xplat:deps_map_utils.bzl", "deps_map_utils")
load("@fbsource//xplat/pfh/Infra_Networking_Core:DEFS.bzl", "Infra_Networking_Core")
load("@prelude//utils:buckconfig.bzl", "read", "read_bool")

# Fizz is a cross platform library used across fbcode, fbobjc, fbandroid, etc.
#
# Each build environment defines a separate set of default warning flags.
# Since we primarily develop within fbcode, this meant that we would see our
# builds pass on our devserver, then fail a sandcastle xplat contbuild job at
# difftime (or worse, some contbuilds are asynchronous so we only find out
# about this after land) since some of these environments define `-Werror`.
#
FIZZ_EXTRA_CXX_WARNINGS = [
    "-Werror=mismatched-tags",
    "-Werror=shadow",
    "-Werror=sign-compare",
]

FIZZ_CXX_WARNINGS = (
    [
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
    ]
    + FIZZ_EXTRA_CXX_WARNINGS
    if ("oe-linux-gcc9" not in read("toolchain", "PROG", ""))
    else []
)

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

WINDOWS_CLANG_CXX_FLAGS = [
    "-Wno-deprecated-declarations",
    "-Wno-microsoft-cast",
    "-DBOOST_HAS_THREADS",
]

# fizz must not opt into SSE4.2 on its own: it changes folly's F14 intrinsics
# mode, which has to match across every object in the link.
WINDOWS_CLANG_SSE4_FLAGS = select({
    "DEFAULT": [],
    "ovr_config//os:windows-gcc-or-clang": select({
        "DEFAULT": [],
        "ovr_config//cpu/x86:avx2": ["-msse4.2"],
        "ovr_config//cpu/x86:sse42": ["-msse4.2"],
    }),
})

DEFAULT_APPLE_SDKS = (APPLETVOS, IOS, MACOSX)
DEFAULT_PLATFORMS = (ANDROID, APPLE, CXX, FBCODE, WINDOWS)

# Tests and binaries build for the host only; FBCODE is what the
# `fbcode//fizz/...` aliases resolve to.
DEFAULT_TOOL_PLATFORMS = (CXX, FBCODE)

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
    srcs = [],
    # cpp_library API
    headers = [],
    private_headers = [],
    modular_headers = None,  # @unused
    deps = None,
    exported_deps = None,
    external_deps = None,
    exported_external_deps = None,
    propagated_pp_flags = (),
    # fb_xplat API
    enable_static_variant = False,
    platforms = None,
    **kwargs,
):
    """Translate a `cpp_library`-style declaration into an `fb_xplat_cxx_library`."""
    converted_deps = deps_map_utils.convert_all_to_fbsource_deps(
        deps = deps,
        exported_deps = exported_deps,
        external_deps = external_deps,
        exported_external_deps = exported_external_deps,
    )
    fizz_cxx_library(
        name = name,
        platforms = platforms,
        exported_headers = headers,
        headers = private_headers,
        srcs = srcs,
        exported_preprocessor_flags = propagated_pp_flags,
        deps = converted_deps.deps,
        exported_deps = converted_deps.exported_deps,
        enable_static_variant = enable_static_variant,
        **kwargs,
    )

def fizz_cxx_library(
    name, platforms = None, apple_sdks = None, headers = [], exported_headers = [], enable_static_variant = False, header_namespace = "", feature = None, srcs = [], **kwargs
):
    """Translate a simpler declartion into the more complete library target"""
    if apple_sdks == None:
        apple_sdks = DEFAULT_APPLE_SDKS
    if platforms == None:
        platforms = DEFAULT_PLATFORMS
    if feature == None:
        feature = Infra_Networking_Core

    sse4_flags = WINDOWS_CLANG_SSE4_FLAGS if read_bool("fizz", "enable_sse4", True) else []

    if headers or exported_headers:
        public_include_directories = []
        header_namespace = _compute_header_namespace()
    else:
        public_include_directories = _compute_include_directories()
        header_namespace = ""

    fb_xplat_cxx_library(
        name = name,
        srcs = srcs if srcs else [],
        # fbcode's `cpp_library` never re-exports `deps`; keep that for the
        # fbcode build so fizz's private deps stay private to its consumers.
        fbcode_reexport_all_header_dependencies = False,
        feature = feature,
        enable_static_variant = enable_static_variant,
        platforms = platforms,
        apple_sdks = apple_sdks,
        headers = headers,
        exported_headers = exported_headers,
        header_namespace = header_namespace,
        public_include_directories = public_include_directories,
        compiler_flags = kwargs.pop("compiler_flags", []) + CXXFLAGS + sse4_flags,
        windows_compiler_flags = kwargs.pop("windows_compiler_flags", []) + WINDOWS_CLANG_CXX_FLAGS,
        fbobjc_compiler_flags = kwargs.pop("fbobjc_compiler_flags", []) + FBOBJC_CXXFLAGS,
        fbobjc_exported_preprocessor_flags = kwargs.pop("fbobjc_exported_preprocessor_flags", []),
        fbandroid_compiler_flags = kwargs.pop("fbandroid_compiler_flags", []) + FBANDROID_CXXFLAGS,
        windows_msvc_compiler_flags_override = kwargs.pop("windows_msvc_compiler_flags_override", WINDOWS_MSVC_CXXFLAGS),
        visibility = kwargs.pop("visibility", ["PUBLIC"]),
        **kwargs,
    )

def fizz_cpp_binary(name, deps, platforms = DEFAULT_TOOL_PLATFORMS, **kwargs):
    converted_deps = deps_map_utils.convert_all_to_fbsource_deps(
        deps = deps,
    )
    fizz_cxx_binary(name = name, deps = converted_deps.deps, platforms = platforms, **kwargs)

def fizz_cxx_binary(name, platforms = DEFAULT_TOOL_PLATFORMS, **kwargs):
    fb_xplat_cxx_binary(name = name, platforms = platforms, contacts = ["oncall+secure_pipes@xmail.facebook.com"], **kwargs)

def fizz_cpp_unittest(
    name,
    deps,
    external_deps = (),
    platforms = DEFAULT_TOOL_PLATFORMS,
    supports_static_listing = True,  # @unused
    source_headers = None,  # @unused
    **kwargs,
):
    converted_deps = deps_map_utils.convert_all_to_fbsource_deps(
        deps = deps,
        external_deps = external_deps,
    )
    fizz_cxx_test(name = name, deps = converted_deps.deps, platforms = platforms, **kwargs)

def fizz_cxx_test(name, platforms = DEFAULT_TOOL_PLATFORMS, **kwargs):
    fb_xplat_cxx_test(name = name, platforms = platforms, contacts = ["oncall+secure_pipes@xmail.facebook.com"], **kwargs)

def fizz_multi_cpp_unittest(name, suffixes_and_constraints, **kwargs):
    if "constraint_overrides" in kwargs:
        fail("'constraint_overrides' not supported in fizz_multi_cxx_test.")
    for suffix, constraints in suffixes_and_constraints:
        actual_name = "{}{}".format(name, suffix)
        fizz_cpp_unittest(
            name = actual_name,
            constraint_overrides = constraints,
            **kwargs,
        )
