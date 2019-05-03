#include <fizz/protocol/clock/SystemClock.h>

namespace fizz {

std::chrono::system_clock::time_point SystemClock::getCurrentTime() const {
  return std::chrono::system_clock::now();
}

} // namespace fizz
