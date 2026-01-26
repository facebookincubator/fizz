# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
#
# NOTE: This file is manually maintained due to optional brotli dependency.

# Header-only interface library
fizz_add_library(fizz_compression_certificate_compressor
  EXPORTED_DEPS fizz_record_record
)

fizz_add_library(fizz_compression_cert_decompression_manager
  SRCS CertDecompressionManager.cpp
  EXPORTED_DEPS fizz_compression_certificate_compressor
)

fizz_add_library(fizz_compression_zlib_certificate_compressor
  SRCS ZlibCertificateCompressor.cpp
  EXPORTED_DEPS fizz_compression_certificate_compressor
  EXTERNAL_DEPS ZLIB::ZLIB
)

fizz_add_library(fizz_compression_zlib_certificate_decompressor
  SRCS ZlibCertificateDecompressor.cpp
  EXPORTED_DEPS fizz_compression_certificate_compressor
  EXTERNAL_DEPS ZLIB::ZLIB
)

fizz_add_library(fizz_compression_zstd_certificate_compressor
  SRCS ZstdCertificateCompressor.cpp
  EXPORTED_DEPS fizz_compression_certificate_compressor
  EXTERNAL_DEPS ${ZSTD_LIBRARY}
)

fizz_add_library(fizz_compression_zstd_certificate_decompressor
  SRCS ZstdCertificateDecompressor.cpp
  EXPORTED_DEPS fizz_compression_certificate_compressor
  EXTERNAL_DEPS ${ZSTD_LIBRARY}
)

# Brotli is optional - only build if found
find_package(Brotli QUIET)
if (Brotli_FOUND OR TARGET brotli::brotlienc)
  set(FIZZ_HAVE_BROTLI TRUE CACHE BOOL "Build with Brotli support")

  fizz_add_library(fizz_compression_brotli_certificate_compressor
    SRCS BrotliCertificateCompressor.cpp
    EXPORTED_DEPS fizz_compression_certificate_compressor
    EXTERNAL_DEPS brotli::brotlienc
  )

  fizz_add_library(fizz_compression_brotli_certificate_decompressor
    SRCS BrotliCertificateDecompressor.cpp
    EXPORTED_DEPS fizz_compression_certificate_compressor
    EXTERNAL_DEPS brotli::brotlidec
  )
endif()
