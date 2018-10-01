/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/extensions/exportedauth/ExportedAuthenticator.h>
#include <fizz/extensions/exportedauth/Util.h>

using namespace folly;

namespace fizz {

Buf ExportedAuthenticator::getAuthenticatorRequest(
    Buf certificateRequestContext,
    std::vector<fizz::Extension> extensions) {
  if (!certificateRequestContext || certificateRequestContext->empty()) {
    throw FizzException(
        "certificate request context must not be empty",
        AlertDescription::illegal_parameter);
  }

  CertificateRequest cr;
  cr.certificate_request_context = std::move(certificateRequestContext);
  cr.extensions = std::move(extensions);
  return encode<CertificateRequest>(std::move(cr));
}

Buf ExportedAuthenticator::getAuthenticator(
    const fizz::server::AsyncFizzServer& transport,
    const SelfCert& cert,
    Buf authenticatorRequest) {
  const auto& state = transport.getState();
  const auto& cipher = *(state.cipher());
  auto deriver = Factory().makeKeyDeriver(cipher);
  auto hashLength = deriver->hashLength();
  auto supportedSchemes = state.context()->getSupportedSigSchemes();
  auto handshakeContext = transport.getEkm(
      "EXPORTER-server authenticator handshake context", nullptr, hashLength);
  auto finishedMacKey = transport.getEkm(
      "EXPORTER-server authenticator finished key", nullptr, hashLength);
  return makeAuthenticator(
      deriver,
      supportedSchemes,
      cert,
      std::move(authenticatorRequest),
      std::move(handshakeContext),
      std::move(finishedMacKey),
      CertificateVerifyContext::Authenticator);
}

Buf ExportedAuthenticator::getAuthenticator(
    const fizz::client::AsyncFizzClient& transport,
    const SelfCert& cert,
    Buf authenticatorRequest) {
  const auto& state = transport.getState();
  const auto& cipher = *(state.cipher());
  auto deriver = Factory().makeKeyDeriver(cipher);
  auto hashLength = deriver->hashLength();
  auto supportedSchemes = state.context()->getSupportedSigSchemes();
  auto handshakeContext = transport.getEkm(
      "EXPORTER-client authenticator handshake context", nullptr, hashLength);
  auto finishedMacKey = transport.getEkm(
      "EXPORTER-client authenticator finished key", nullptr, hashLength);
  return makeAuthenticator(
      deriver,
      supportedSchemes,
      cert,
      std::move(authenticatorRequest),
      std::move(handshakeContext),
      std::move(finishedMacKey),
      CertificateVerifyContext::Authenticator);
}

Buf ExportedAuthenticator::getAuthenticatorContext(Buf authenticator) {
  folly::IOBufQueue authQueue{folly::IOBufQueue::cacheChainLength()};
  authQueue.append(std::move(authenticator));
  auto param = fizz::ReadRecordLayer::decodeHandshakeMessage(authQueue);
  auto& certMsg = boost::get<CertificateMsg>(*param);
  return std::move(certMsg.certificate_request_context);
}

Buf ExportedAuthenticator::makeAuthenticator(
    std::unique_ptr<KeyDerivation>& kderiver,
    std::vector<SignatureScheme> supportedSchemes,
    const SelfCert& cert,
    Buf authenticatorRequest,
    Buf handshakeContext,
    Buf finishedMacKey,
    CertificateVerifyContext context) {
  Buf certificateRequestContext;
  std::vector<fizz::Extension> extensions;
  std::tie(certificateRequestContext, extensions) =
      detail::decodeAuthRequest(authenticatorRequest);
  folly::Optional<SignatureScheme> scheme =
      detail::getSignatureScheme(supportedSchemes, cert, extensions);
  // No proper signature scheme could be selected, return an empty
  // authenticator.
  if (!scheme) {
    auto emptyAuth = detail::getEmptyAuthenticator(
        kderiver,
        std::move(authenticatorRequest),
        std::move(handshakeContext),
        std::move(finishedMacKey));
    return emptyAuth;
  }

  CertificateMsg certificate =
      cert.getCertMessage(std::move(certificateRequestContext));
  auto encodedCertMsg = encodeHandshake(std::move(certificate));
  // Compute CertificateVerify.
  auto transcript = detail::computeTranscript(
      handshakeContext, authenticatorRequest, encodedCertMsg);
  auto transcriptHash = detail::computeTranscriptHash(kderiver, transcript);
  auto sig = cert.sign(*scheme, context, transcriptHash->coalesce());
  CertificateVerify verify;
  verify.algorithm = *scheme;
  verify.signature = std::move(sig);
  auto encodedCertificateVerify = encodeHandshake(std::move(verify));
  // Compute Finished.
  auto finishedTranscript =
      detail::computeFinishedTranscript(transcript, encodedCertificateVerify);
  auto finishedTranscriptHash =
      detail::computeTranscriptHash(kderiver, finishedTranscript);
  auto verifyData =
      detail::getFinishedData(kderiver, finishedMacKey, finishedTranscriptHash);
  Finished finished;
  finished.verify_data = std::move(verifyData);
  auto encodedFinished = encodeHandshake(std::move(finished));

  return detail::computeTranscript(
      encodedCertMsg, encodedCertificateVerify, encodedFinished);
}

namespace detail {

std::tuple<Buf, std::vector<fizz::Extension>> decodeAuthRequest(
    const Buf& authRequest) {
  Buf certRequestContext;
  std::vector<fizz::Extension> exts;
  if (authRequest && !(authRequest->empty())) {
    folly::io::Cursor cursor(authRequest.get());
    CertificateRequest decodedCertRequest = decode<CertificateRequest>(cursor);
    certRequestContext =
        std::move(decodedCertRequest.certificate_request_context);
    exts = std::move(decodedCertRequest.extensions);
  } else {
    certRequestContext = folly::IOBuf::copyBuffer("");
  }
  return std::make_tuple(std::move(certRequestContext), std::move(exts));
}

Buf computeTranscriptHash(
    std::unique_ptr<KeyDerivation>& deriver,
    const Buf& toBeHashed) {
  auto hashLength = deriver->hashLength();
  auto data = folly::IOBuf::create(hashLength);
  data->append(hashLength);
  auto transcriptHash =
      folly::MutableByteRange(data->writableData(), data->length());
  deriver->hash(*toBeHashed, transcriptHash);
  return data;
}

void writeBuf(const Buf& buf, folly::io::Appender& out) {
  if (buf && !(buf->empty())) {
    auto current = buf.get();
    size_t chainElements = buf->countChainElements();
    for (size_t i = 0; i < chainElements; ++i) {
      out.push(current->data(), current->length());
      current = current->next();
    }
  }
}

Buf computeTranscript(
    const Buf& handshakeContext,
    const Buf& authenticatorRequest,
    const Buf& certificate) {
  constexpr uint16_t capacity = 256;
  auto out = folly::IOBuf::create(capacity);
  folly::io::Appender appender(out.get(), capacity);
  detail::writeBuf(handshakeContext, appender);
  detail::writeBuf(authenticatorRequest, appender);
  detail::writeBuf(certificate, appender);
  return out;
}

Buf computeFinishedTranscript(const Buf& crTranscript, const Buf& certVerify) {
  constexpr uint16_t capacity = 256;
  auto out = folly::IOBuf::create(capacity);
  folly::io::Appender appender(out.get(), capacity);
  detail::writeBuf(crTranscript, appender);
  detail::writeBuf(certVerify, appender);
  return out;
}

Buf getFinishedData(
    std::unique_ptr<KeyDerivation>& deriver,
    Buf& finishedMacKey,
    const Buf& finishedTranscript) {
  auto hashLength = deriver->hashLength();
  auto data = folly::IOBuf::create(hashLength);
  data->append(hashLength);
  auto outRange = folly::MutableByteRange(data->writableData(), data->length());
  deriver->hmac(finishedMacKey->coalesce(), *finishedTranscript, outRange);
  return data;
}

folly::Optional<std::vector<SignatureScheme>> getRequestedSchemes(
    const std::vector<fizz::Extension>& authRequestExtensions) {
  if (!(authRequestExtensions.empty())) {
    auto sigAlgsExtension =
        getExtension<SignatureAlgorithms>(authRequestExtensions);
    if (sigAlgsExtension) {
      auto requestedSchemes = sigAlgsExtension->supported_signature_algorithms;
      return requestedSchemes;
    } else {
      return folly::none;
    }
  } else {
    return folly::none;
  }
}

folly::Optional<SignatureScheme> getSignatureScheme(
    const std::vector<SignatureScheme>& supportedSchemes,
    const SelfCert& cert,
    const std::vector<fizz::Extension>& authRequestExtensions) {
  folly::Optional<SignatureScheme> selectedScheme;
  const auto certSchemes = cert.getSigSchemes();
  folly::Optional<std::vector<SignatureScheme>> requestedSchemes =
      getRequestedSchemes(authRequestExtensions);
  if (requestedSchemes) {
    for (const auto& scheme : supportedSchemes) {
      if (std::find(certSchemes.begin(), certSchemes.end(), scheme) !=
              certSchemes.end() &&
          std::find(
              (*requestedSchemes).begin(), (*requestedSchemes).end(), scheme) !=
              (*requestedSchemes).end()) {
        selectedScheme = scheme;
        break;
      }
    }
  }

  if (!selectedScheme) {
    VLOG(1) << "authenticator request without proper signature algorithms";
    for (const auto& scheme : supportedSchemes) {
      if (std::find(certSchemes.begin(), certSchemes.end(), scheme) !=
          certSchemes.end()) {
        selectedScheme = scheme;
        break;
      }
    }
  }
  return selectedScheme;
}

Buf getEmptyAuthenticator(
    std::unique_ptr<KeyDerivation>& kderiver,
    Buf authRequest,
    Buf handshakeContext,
    Buf finishedMacKey) {
  CertificateMsg emptyCertMsg;
  emptyCertMsg.certificate_request_context =
      std::get<0>(detail::decodeAuthRequest(authRequest));
  auto encodedEmptyCertMsg = encodeHandshake(std::move(emptyCertMsg));
  auto emptyAuthTranscript = detail::computeTranscript(
      handshakeContext, authRequest, encodedEmptyCertMsg);
  auto emptyAuthTranscriptHash =
      detail::computeTranscriptHash(kderiver, emptyAuthTranscript);
  auto finVerify = detail::getFinishedData(
      kderiver, finishedMacKey, emptyAuthTranscriptHash);
  Finished emptyAuth;
  emptyAuth.verify_data = std::move(finVerify);
  auto encodedEmptyAuth = encodeHandshake(std::move(emptyAuth));
  return encodedEmptyAuth;
}

} // namespace detail
} // namespace fizz
