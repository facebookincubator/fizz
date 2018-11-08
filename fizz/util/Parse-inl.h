#include <fizz/record/Types.h>
#include <map>

namespace fizz {
template <>
inline CipherSuite parse(folly::StringPiece s) {
  static const std::map<folly::StringPiece, CipherSuite> stringToCiphers = {
      {"TLS_AES_128_GCM_SHA256", CipherSuite::TLS_AES_128_GCM_SHA256},
      {"TLS_AES_256_GCM_SHA384", CipherSuite::TLS_AES_256_GCM_SHA384},
      {"TLS_CHACHA20_POLY1305_SHA256",
       CipherSuite::TLS_CHACHA20_POLY1305_SHA256},
      {"TLS_AES_128_OCB_SHA256_EXPERIMENTAL",
       CipherSuite::TLS_AES_128_OCB_SHA256_EXPERIMENTAL}};

  auto location = stringToCiphers.find(s);
  if (location != stringToCiphers.end()) {
    return location->second;
  }

  throw std::runtime_error(folly::to<std::string>("Unknown cipher suite: ", s));
}

template <>
inline NamedGroup parse(folly::StringPiece s) {
  static const std::map<folly::StringPiece, NamedGroup> stringToGroups = {
      {"secp256r1", NamedGroup::secp256r1}, {"x25519", NamedGroup::x25519}};

  auto location = stringToGroups.find(s);
  if (location != stringToGroups.end()) {
    return location->second;
  }

  throw std::runtime_error(folly::to<std::string>("Unknown named group: ", s));
}
} // namespace fizz
