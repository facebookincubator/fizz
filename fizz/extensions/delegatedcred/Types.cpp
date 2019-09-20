#include <fizz/extensions/delegatedcred/Types.h>
#include <fizz/record/Types.h>

#include <folly/String.h>
#include <folly/io/Cursor.h>

using namespace fizz::extensions;

namespace fizz {

template <>
folly::Optional<DelegatedCredential> getExtension(
    const std::vector<Extension>& extensions) {
  auto it = findExtension(extensions, ExtensionType::delegated_credential);
  if (it == extensions.end()) {
    return folly::none;
  }
  DelegatedCredential cred;
  folly::io::Cursor cursor(it->extension_data.get());
  detail::read(cred.valid_time, cursor);
  detail::read(cred.expected_verify_scheme, cursor);
  detail::readBuf<detail::bits24>(cred.public_key, cursor);
  detail::read(cred.credential_scheme, cursor);
  detail::readBuf<uint16_t>(cred.signature, cursor);
  return std::move(cred);
}

template <>
folly::Optional<DelegatedCredentialSupport> getExtension(
    const std::vector<Extension>& extensions) {
  auto it = findExtension(extensions, ExtensionType::delegated_credential);
  if (it == extensions.end()) {
    return folly::none;
  }
  return DelegatedCredentialSupport();
}

template <>
Extension encodeExtension(const DelegatedCredential& cred) {
  Extension ext;
  ext.extension_type = ExtensionType::delegated_credential;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 10);
  detail::write(cred.valid_time, appender);
  detail::write(cred.expected_verify_scheme, appender);
  detail::writeBuf<detail::bits24>(cred.public_key, appender);
  detail::write(cred.credential_scheme, appender);
  detail::writeBuf<uint16_t>(cred.signature, appender);
  return ext;
}

template <>
Extension encodeExtension(const DelegatedCredentialSupport&) {
  Extension ext;
  ext.extension_type = ExtensionType::delegated_credential;
  ext.extension_data = folly::IOBuf::create(0);
  return ext;
}

} // namespace fizz
