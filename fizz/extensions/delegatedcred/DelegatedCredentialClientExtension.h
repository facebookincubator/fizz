#pragma once

#include <fizz/client/ClientExtensions.h>
#include <fizz/extensions/delegatedcred/Types.h>

namespace fizz {
namespace extensions {

class DelegatedCredentialClientExtension : public ClientExtensions {
 public:
  std::vector<Extension> getClientHelloExtensions() const override;

  void onEncryptedExtensions(const std::vector<Extension>& extensions) override;
};
} // namespace extensions
} // namespace fizz
