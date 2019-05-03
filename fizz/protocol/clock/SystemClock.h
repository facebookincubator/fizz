#pragma once

#include <fizz/protocol/clock/Clock.h>

namespace fizz {

class SystemClock : public Clock {
  std::chrono::system_clock::time_point getCurrentTime() const override;
};

} // namespace fizz
