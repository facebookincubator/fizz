#include <fizz/protocol/clock/Clock.h>
#include <folly/portability/GMock.h>

namespace fizz {
namespace test {

class MockClock : public Clock {
 public:
  MOCK_CONST_METHOD0(getCurrentTime, std::chrono::system_clock::time_point());
};

} // namespace test
} // namespace fizz
