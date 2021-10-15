#include <fizz/experimental/ktls/FizzKTLSCallback.h>

namespace fizz {

void KTLSCallbackImpl::receivedNewSessionTicket(
    AsyncKTLSSocket*,
    fizz::NewSessionTicket nst) {
  if (!ticketHandler_ || !keyScheduler_) {
    return;
  }
  ticketHandler_(*keyScheduler_, std::move(nst));
}
} // namespace fizz
