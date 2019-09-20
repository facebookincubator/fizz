#include <fizz/extensions/delegatedcred/DelegatedCredentialClientExtension.h>

namespace fizz {
namespace extensions {

std::vector<Extension>
DelegatedCredentialClientExtension::getClientHelloExtensions() const {
  std::vector<Extension> clientExtensions;
  clientExtensions.push_back(encodeExtension(DelegatedCredentialSupport()));
  return clientExtensions;
}

void DelegatedCredentialClientExtension::onEncryptedExtensions(
    const std::vector<Extension>& extensions) {}
} // namespace extensions
} // namespace fizz
