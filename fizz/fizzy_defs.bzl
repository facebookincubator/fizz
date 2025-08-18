# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
load("@fbsource//tools/build_defs:fb_xplat_cxx_library.bzl", "fb_xplat_cxx_library")
load(":defs.bzl", "CXXFLAGS")

FIZZY_CXXFLAGS = [
    "-fvisibility=hidden",
    "-Werror=switch",
]

FIZZY_PUBLIC_HEADERS = [
    "facebook/fizzy/include/fizzy/compiler.h",
    "facebook/fizzy/include/fizzy/error.h",
    "facebook/fizzy/include/fizzy/io.h",
    "facebook/fizzy/include/fizzy/certificate.h",
    "facebook/fizzy/include/fizzy/client.h",
    "facebook/fizzy/include/fizzy/factory.h",
    "facebook/fizzy/include/fizzy/protocol.h",
    "facebook/fizzy/include/fizzy/tls_params.h",
]

FIZZY_INTERNAL_HEADERS = [
    "facebook/fizzy/src/async/async_run_sm.h",
    "facebook/fizzy/src/async/async_write.h",
    "facebook/fizzy/src/sm/client.h",
    "facebook/fizzy/src/async.h",
    "facebook/fizzy/src/io.h",
    "facebook/fizzy/src/smio.h",
    "facebook/fizzy/src/base.h",
    "facebook/fizzy/src/cast.h",
    "facebook/fizzy/src/certificate.h",
    "facebook/fizzy/src/client.h",
    "facebook/fizzy/src/factory.h",
]

FIZZY_SRCS = [
    "facebook/fizzy/src/async/async_write.cpp",
    "facebook/fizzy/src/async/async_run_sm.cpp",
    "facebook/fizzy/src/sm/client.cpp",
    "facebook/fizzy/src/io.cpp",
    "facebook/fizzy/src/certificate.cpp",
    "facebook/fizzy/src/protocol.cpp",
    "facebook/fizzy/src/client.cpp",
    "facebook/fizzy/src/factory.cpp",
    "facebook/fizzy/src/tls_params.cpp",
]

COMMON_FLAGS = [] + select({
    "DEFAULT": [],
    "fbsource//xplat/fizz/constraints:fizzy-user-must-set-factory-explicitly": [
        "-DFIZZY_USER_MUST_SET_FACTORY",
    ],
})

def fizzy_library(name):
    fb_xplat_cxx_library(
        name = name,
        raw_headers = FIZZY_INTERNAL_HEADERS + FIZZY_PUBLIC_HEADERS,
        public_include_directories = ["facebook/fizzy/include"],
        include_directories = [
            "facebook/fizzy/src",
        ],
        compiler_flags = CXXFLAGS + FIZZY_CXXFLAGS,
        srcs = FIZZY_SRCS,
        visibility = ["PUBLIC"],
        deps = [
            "fbsource//xplat/fizz/client:fizz_client_context",
            "fbsource//xplat/fizz/client:fizz_client",
            "fbsource//xplat/fizz/client:psk_serialization_utils",
            "fbsource//xplat/fizz/protocol:certificate_verifier",
            "fbsource//third-party/boost:boost",
        ] + select({
            "DEFAULT": [
                "fbsource//xplat/fizz/protocol:default_factory",
            ],
            "fbsource//xplat/fizz/constraints:fizzy-user-must-set-factory-explicitly": [
                "fbsource//xplat/fizz/facebook/protocol:dispatch_factory",
            ],
        }),
        preprocessor_flags = COMMON_FLAGS,
    )

    fb_xplat_cxx_library(
        name = "{}__internal-headers".format(name),
        raw_headers = FIZZY_INTERNAL_HEADERS,
        public_include_directories = ["facebook/fizzy/src/"],
        visibility = ["//xplat/fizz/..."],
    )

    fb_xplat_cxx_library(
        name = name + "_mnscrypto_factory",
        raw_headers = FIZZY_INTERNAL_HEADERS + [
            "facebook/fizzy/include/fizzy/factories/mnscrypto.h",
        ],
        public_include_directories = ["facebook/fizzy/include"],
        include_directories = [
            "facebook/fizzy/src",
        ],
        compiler_flags = CXXFLAGS + FIZZY_CXXFLAGS,
        srcs = [
            "facebook/fizzy/src/factories/mnscrypto.cpp",
        ],
        preprocessor_flags = COMMON_FLAGS,
        visibility = ["PUBLIC"],
        deps = [
            ":" + name,
            "fbsource//xplat/fizz/facebook/protocol:mnscrypto_factory",
        ],
    )
