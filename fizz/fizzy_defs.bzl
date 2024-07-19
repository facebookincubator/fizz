load("@fbsource//tools/build_defs:fb_xplat_cxx_library.bzl", "fb_xplat_cxx_library")
load(":defs.bzl", "CXXFLAGS")

FIZZY_CXXFLAGS = [
    "-fvisibility=hidden",
]

FIZZY_PUBLIC_RAW_HEADERS_GLOBEXPR = "facebook/fizzy/include/**/*.h"
FIZZY_INTERNAL_RAW_HEADERS_GLOBEXPR = "facebook/fizzy/src/**/*.h"

def fizzy_library(name):
    fb_xplat_cxx_library(
        name = name,
        raw_headers = native.glob([FIZZY_PUBLIC_RAW_HEADERS_GLOBEXPR, FIZZY_INTERNAL_RAW_HEADERS_GLOBEXPR]),
        public_include_directories = ["facebook/fizzy/include"],
        include_directories = [
            "facebook/fizzy/src",
        ],
        compiler_flags = CXXFLAGS + FIZZY_CXXFLAGS,
        srcs = native.glob(["facebook/fizzy/src/**/*.c", "facebook/fizzy/src/**/*.cpp"]),
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
        raw_headers = native.glob([FIZZY_INTERNAL_RAW_HEADERS_GLOBEXPR]),
        public_include_directories = ["facebook/fizzy/src/"],
        visibility = ["//xplat/fizz/..."],
    )
