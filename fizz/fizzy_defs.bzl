load("@fbsource//tools/build_defs:fb_xplat_cxx_library.bzl", "fb_xplat_cxx_library")
load(":defs.bzl", "CXXFLAGS")

FIZZY_CXXFLAGS = [
    "-fvisibility=hidden",
]

FIZZY_PUBLIC_HEADERS = [
    "facebook/fizzy/include/fizzy/compiler.h",
    "facebook/fizzy/include/fizzy/error.h",
    "facebook/fizzy/include/fizzy/io.h",
    "facebook/fizzy/include/fizzy/certificate.h",
    "facebook/fizzy/include/fizzy/client.h",
    "facebook/fizzy/include/fizzy/protocol.h",
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
]

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
            ":client_fizz_client_context",
            ":client_fizz_client",
            ":client_psk_serialization",
            ":protocol_default_factory",
            "fbsource//third-party/boost:boost",
        ],
    )

    fb_xplat_cxx_library(
        name = "{}__internal-headers".format(name),
        raw_headers = FIZZY_INTERNAL_HEADERS,
        public_include_directories = ["facebook/fizzy/src/"],
        visibility = ["//xplat/fizz/..."],
    )
