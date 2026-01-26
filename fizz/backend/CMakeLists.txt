# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
#
# NOTE: This file is manually maintained due to conditional libaegis/liboqs logic.

fizz_add_library(fizz_backend_libaegis
  SRCS libaegis/AEGISCipher.cpp
  EXPORTED_DEPS
    fizz_config
    fizz_crypto_aead_aead
    fizz_crypto_aead_cryptoutil
    fizz_crypto_crypto
    Folly::folly_lang_checked_math
)
if (FIZZ_HAVE_LIBAEGIS)
  if(BUILD_SHARED_LIBS)
    target_link_libraries(fizz_backend_libaegis INTERFACE aegis::aegis)
  else()
    target_link_libraries(fizz_backend_libaegis PUBLIC aegis::aegis)
  endif()
  target_link_libraries(fizz_backend_libaegis_obj PUBLIC aegis::aegis)
endif()

fizz_add_library(fizz_backend_liboqs
  SRCS liboqs/OQSKeyExchange.cpp
  EXPORTED_DEPS
    fizz_config
    fizz_crypto_crypto
    fizz_crypto_exchange_key_exchange
    Folly::folly_memory
)
if (FIZZ_HAVE_OQS)
  if(BUILD_SHARED_LIBS)
    target_link_libraries(fizz_backend_liboqs INTERFACE OQS::oqs)
  else()
    target_link_libraries(fizz_backend_liboqs PUBLIC OQS::oqs)
  endif()
  target_link_libraries(fizz_backend_liboqs_obj PUBLIC OQS::oqs)
endif()

fizz_add_library(fizz_backend_openssl
  SRCS
    openssl/certificate/CertUtils.cpp
    openssl/crypto/OpenSSLKeyUtils.cpp
    openssl/crypto/Sha.cpp
    openssl/crypto/aead/OpenSSLEVPCipher.cpp
    openssl/crypto/exchange/OpenSSLKeyExchange.cpp
    openssl/crypto/signature/Signature.cpp
  EXPORTED_DEPS
    fizz_compression_certificate_compressor
    fizz_config
    fizz_crypto_aead_aead
    fizz_crypto_aead_cryptoutil
    fizz_crypto_aead_iobuf
    fizz_crypto_crypto
    fizz_crypto_exchange_key_exchange
    fizz_crypto_hasher
    fizz_crypto_hkdf
    fizz_protocol_certificate
    fizz_record_record
    Folly::folly_conv
    Folly::folly_io_async_ssl_openssl_transport_certificate
    Folly::folly_io_iobuf
    Folly::folly_lang_assume
    Folly::folly_lang_bits
    Folly::folly_lang_checked_math
    Folly::folly_memory
    Folly::folly_portability_openssl
    Folly::folly_range
    Folly::folly_ssl_openssl_cert_utils
    Folly::folly_ssl_openssl_hash
    Folly::folly_ssl_openssl_ptr_types
    Folly::folly_string
)

fizz_add_library(fizz_backend_libsodium
  SRCS libsodium/crypto/exchange/X25519.cpp
  EXPORTED_DEPS
    fizz_crypto_crypto
    fizz_crypto_exchange_key_exchange
    Folly::folly_conv
    Folly::folly_io_iobuf
    Folly::folly_optional
    Folly::folly_range
)
