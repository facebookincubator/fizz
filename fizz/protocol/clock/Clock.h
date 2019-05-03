#pragma once

#include <chrono>

namespace fizz {

// Simple clock abstraction to facilitate testing.
class Clock {
 public:
  virtual ~Clock() = default;
  virtual std::chrono::system_clock::time_point getCurrentTime() const = 0;
};

} // namespace fizz
