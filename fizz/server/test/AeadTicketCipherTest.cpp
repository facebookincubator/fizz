/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <fizz/server/AeadTicketCipher.h>

#include <fizz/crypto/aead/test/Mocks.h>
#include <fizz/crypto/test/Mocks.h>
#include <fizz/crypto/test/TestUtil.h>
#include <fizz/protocol/clock/test/Mocks.h>
#include <folly/String.h>

using namespace fizz::test;
using namespace folly;
using namespace testing;

static constexpr StringPiece ticketSecret1{
    "90a791cf38c0b5c20447ef029ae1bc4bf3eecc2e85042174497671835ceaccd9"};
// secret: 13deec41c45b2f1c4f595ad5972d13047fba09031ba53140c751380e74114cc4
// salt: 4444444444444444444444444444444444444444444444444444444444444444
// hkdf output: c951156f3dcb1ab243a3f2c8e4346bec92cb25d241ae821484081388
static constexpr StringPiece ticket1{
    "444444444444444444444444444444444444444444444444444444444444444400000000579bb5b10c83d7a581f6b8f7bd25acde3dabfe6f59e5147bde86681831"};
static constexpr StringPiece ticket2{
    "444444444444444444444444444444444444444444444444444444444444444400000001f444b4f0a0d1dd8b26d3a0afa275b4f6956cfdce4857f9ec46177d0ff9"};

static constexpr StringPiece ticketSecret2{
    "04de0343a34c12f17f8b9696443d55e533ca1eef92bdba6634a46b604e51436d"};
// secret: d2c07e1107d3024bd08ebf34d59b9726d05bd7082da80cbb1e90b879e0770b5f
// salt: 5cef31d266ca1fe1d634de9b95668d3d8895d4837d3ba81787185ff51c056e95
// hkdf output: f7d80b07236875b5a48bdc5bd4642a775c05c231b9507285675c1e0b
static constexpr StringPiece ticket3{
    "5cef31d266ca1fe1d634de9b95668d3d8895d4837d3ba81787185ff51c056e95000000005d19a72a3becb5b063346fdf1ec6f9d9d4ddd82cb5f34a8ba0d19e4b69"};

// Uses context 'foobar'
static constexpr StringPiece ticket4{
    "5cef31d266ca1fe1d634de9b95668d3d8895d4837d3ba81787185ff51c056e95000000005b2168cc0fda4f9987b5e9d045845ba4809ac5189158c578c0e5d11b00"};

static constexpr StringPiece badTicket{
    "5d19a72a3becb5b061346fdf1ec6f9d9d4ddd82cb5f34a8ba0d19e4b69"};

namespace fizz {
namespace server {
namespace test {

class MockTicketCodecInstance {
 public:
  MOCK_CONST_METHOD1(_encode, Buf(ResumptionState& state));
  MOCK_CONST_METHOD2(
      _decode,
      ResumptionState(Buf& encoded, const FizzServerContext* context));
};

class MockTicketCodec {
 public:
  static constexpr folly::StringPiece Label{"Mock Ticket Codec"};
  static Buf encode(ResumptionState state) {
    return instance->_encode(state);
  }
  static ResumptionState decode(Buf encoded, const FizzServerContext* context) {
    return instance->_decode(encoded, context);
  }
  static MockTicketCodecInstance* instance;
};
MockTicketCodecInstance* MockTicketCodec::instance;
constexpr folly::StringPiece MockTicketCodec::Label;

using TestAeadTicketCipher = AeadTicketCipher<
    OpenSSLEVPCipher<AESGCM128>,
    MockTicketCodec,
    HkdfImpl<Sha256>>;

class AeadTicketCipherTest : public Test {
 public:
  ~AeadTicketCipherTest() override = default;
  void SetUp() override {
    MockTicketCodec::instance = &codec_;
    clock_ = std::make_shared<MockClock>();
    cipher_.setClock(clock_);
  }

 protected:
  TestAeadTicketCipher cipher_;
  MockTicketCodecInstance codec_;
  std::shared_ptr<MockClock> clock_;

  void setTicketSecrets(std::string pskContext = "") {
    if (!pskContext.empty()) {
      cipher_ = TestAeadTicketCipher(pskContext);
    } else {
      cipher_ = TestAeadTicketCipher();
    }
    cipher_.setClock(clock_);
    auto s1 = toIOBuf(ticketSecret1);
    auto s2 = toIOBuf(ticketSecret2);
    std::vector<ByteRange> ticketSecrets{{s1->coalesce(), s2->coalesce()}};
    EXPECT_TRUE(cipher_.setTicketSecrets(std::move(ticketSecrets)));
  }

  void expectDecode() {
    EXPECT_CALL(codec_, _decode(_, _))
        .WillOnce(
            Invoke([](Buf& encoded, const FizzServerContext* /*context*/) {
              EXPECT_TRUE(
                  IOBufEqualTo()(encoded, IOBuf::copyBuffer("encodedticket")));
              return ResumptionState();
            }));
  }

  void checkUnsetEncrypt() {
    ResumptionState state;
    EXPECT_FALSE(cipher_.encrypt(std::move(state)).get().hasValue());
  }
};

TEST_F(AeadTicketCipherTest, TestEncryptNoTicketSecrets) {
  checkUnsetEncrypt();
}

TEST_F(AeadTicketCipherTest, TestEncrypt) {
  setTicketSecrets();
  useMockRandom();
  cipher_.setTicketValidity(std::chrono::seconds(5));
  EXPECT_CALL(codec_, _encode(_)).WillOnce(InvokeWithoutArgs([]() {
    return IOBuf::copyBuffer("encodedticket");
  }));
  ResumptionState state;
  auto result = cipher_.encrypt(std::move(state)).get();
  EXPECT_TRUE(result.hasValue());
  EXPECT_TRUE(IOBufEqualTo()(result->first, toIOBuf(ticket1)));
  EXPECT_EQ(result->second, std::chrono::seconds(5));
}

TEST_F(AeadTicketCipherTest, TestHandshakeExpiration) {
  setTicketSecrets();
  useMockRandom();
  cipher_.setHandshakeValidity(std::chrono::seconds(4));
  cipher_.setTicketValidity(std::chrono::seconds(2));
  auto time = std::chrono::system_clock::now();
  EXPECT_CALL(*clock_, getCurrentTime()).WillOnce(Return(time));

  EXPECT_CALL(codec_, _encode(_)).WillOnce(InvokeWithoutArgs([]() {
    return IOBuf::copyBuffer("encodedticket");
  }));
  EXPECT_CALL(codec_, _decode(_, _))
      .Times(2)
      .WillRepeatedly(InvokeWithoutArgs([time]() {
        ResumptionState res;
        res.handshakeTime = time;
        return res;
      }));
  ResumptionState state;
  state.handshakeTime = time;
  auto result = cipher_.encrypt(std::move(state)).get();
  EXPECT_TRUE(result.hasValue());
  EXPECT_TRUE(IOBufEqualTo()(result->first, toIOBuf(ticket1)));
  EXPECT_EQ(result->second, std::chrono::seconds(2));
  EXPECT_CALL(*clock_, getCurrentTime())
      .WillOnce(Return(time + std::chrono::seconds(1)));
  auto decResult = cipher_.decrypt(result->first->clone()).get();
  EXPECT_EQ(decResult.first, PskType::Resumption);
  EXPECT_TRUE(decResult.second.hasValue());
  EXPECT_CALL(*clock_, getCurrentTime())
      .WillOnce(Return(time + std::chrono::seconds(5)));
  auto badResult = cipher_.decrypt(result->first->clone()).get();
  EXPECT_EQ(badResult.first, PskType::Rejected);
  EXPECT_FALSE(badResult.second.hasValue());
}

TEST_F(AeadTicketCipherTest, TestTicketLifetime) {
  setTicketSecrets();
  useMockRandom();
  cipher_.setHandshakeValidity(std::chrono::seconds(4));
  cipher_.setTicketValidity(std::chrono::seconds(2));
  auto time = std::chrono::system_clock::now();

  EXPECT_CALL(codec_, _encode(_))
      .Times(3)
      .WillRepeatedly(InvokeWithoutArgs(
          []() { return IOBuf::copyBuffer("encodedticket"); }));

  // At handshake time, expect ticket validity.
  EXPECT_CALL(*clock_, getCurrentTime()).WillOnce(Return(time));
  ResumptionState state;
  state.handshakeTime = time;
  auto result = cipher_.encrypt(std::move(state)).get();
  EXPECT_TRUE(result.hasValue());
  EXPECT_TRUE(IOBufEqualTo()(result->first, toIOBuf(ticket1)));
  EXPECT_EQ(result->second, std::chrono::seconds(2));

  // At 3 seconds in, expect 1 second (remaining handshake validity)
  EXPECT_CALL(*clock_, getCurrentTime())
      .WillOnce(Return(time + std::chrono::seconds(3)));
  auto result2 = cipher_.encrypt(std::move(state)).get();
  EXPECT_TRUE(result2.hasValue());
  EXPECT_TRUE(IOBufEqualTo()(result2->first, toIOBuf(ticket1)));
  EXPECT_EQ(result2->second, std::chrono::seconds(1));

  // 5 seconds in, no longer valid. Expect none.
  EXPECT_CALL(*clock_, getCurrentTime())
      .WillOnce(Return(time + std::chrono::seconds(5)));
  auto result3 = cipher_.encrypt(std::move(state)).get();
  EXPECT_FALSE(result3.hasValue());
}

TEST_F(AeadTicketCipherTest, TestEncryptExpiredHandshakeTicket) {
  setTicketSecrets();
  useMockRandom();
  cipher_.setHandshakeValidity(std::chrono::seconds(4));
  auto time = std::chrono::system_clock::now();
  EXPECT_CALL(*clock_, getCurrentTime()).WillOnce(Return(time));

  EXPECT_CALL(codec_, _encode(_)).WillOnce(InvokeWithoutArgs([]() {
    return IOBuf::copyBuffer("encodedticket");
  }));
  ResumptionState state;
  state.handshakeTime = time - std::chrono::seconds(5);
  auto result = cipher_.encrypt(std::move(state)).get();
  EXPECT_FALSE(result.hasValue());
}

TEST_F(AeadTicketCipherTest, TestEncryptTicketFromFuture) {
  setTicketSecrets();
  useMockRandom();
  cipher_.setTicketValidity(std::chrono::seconds(2));
  cipher_.setHandshakeValidity(std::chrono::seconds(4));
  auto time = std::chrono::system_clock::now();
  EXPECT_CALL(*clock_, getCurrentTime()).WillOnce(Return(time));

  EXPECT_CALL(codec_, _encode(_)).WillOnce(InvokeWithoutArgs([]() {
    return IOBuf::copyBuffer("encodedticket");
  }));
  ResumptionState state;
  // Ticket was created in the future. Validity period should be equal
  // to maximum (as we can't be sure how old it really is)
  state.handshakeTime = time + std::chrono::seconds(5);
  auto result = cipher_.encrypt(std::move(state)).get();
  EXPECT_TRUE(result.hasValue());
  EXPECT_TRUE(IOBufEqualTo()(result->first, toIOBuf(ticket1)));
  EXPECT_EQ(result->second, std::chrono::seconds(2));
}

TEST_F(AeadTicketCipherTest, TestDecryptNoTicketSecrets) {
  auto result = cipher_.decrypt(toIOBuf(ticket1)).get();
  EXPECT_EQ(result.first, PskType::Rejected);
  EXPECT_FALSE(result.second.hasValue());
}

TEST_F(AeadTicketCipherTest, TestDecryptFirst) {
  setTicketSecrets();
  expectDecode();
  auto result = cipher_.decrypt(toIOBuf(ticket1)).get();
  EXPECT_EQ(result.first, PskType::Resumption);
  EXPECT_TRUE(result.second.hasValue());
}

TEST_F(AeadTicketCipherTest, TestDecryptSecond) {
  setTicketSecrets();
  expectDecode();
  auto result = cipher_.decrypt(toIOBuf(ticket3)).get();
  EXPECT_EQ(result.first, PskType::Resumption);
  EXPECT_TRUE(result.second.hasValue());
}

TEST_F(AeadTicketCipherTest, TestDecryptWithContext) {
  setTicketSecrets("foobar");
  expectDecode();
  auto result = cipher_.decrypt(toIOBuf(ticket4)).get();
  EXPECT_EQ(result.first, PskType::Resumption);
  EXPECT_TRUE(result.second.hasValue());
}

TEST_F(AeadTicketCipherTest, TestDecryptWithoutContext) {
  setTicketSecrets();
  // Ticket 4 needs context 'foobar'
  auto result = cipher_.decrypt(toIOBuf(ticket4)).get();
  EXPECT_EQ(result.first, PskType::Rejected);
  EXPECT_FALSE(result.second.hasValue());
}

TEST_F(AeadTicketCipherTest, TestDecryptWithWrongContext) {
  setTicketSecrets("barbaz");
  // barbaz =/= foobar
  auto result = cipher_.decrypt(toIOBuf(ticket4)).get();
  EXPECT_EQ(result.first, PskType::Rejected);
  EXPECT_FALSE(result.second.hasValue());
}

TEST_F(AeadTicketCipherTest, TestDecryptWithUnneededContext) {
  setTicketSecrets("foobar");
  // Now test that ticket 3 with context 'foobar' doesn't work
  auto result = cipher_.decrypt(toIOBuf(ticket3)).get();
  EXPECT_EQ(result.first, PskType::Rejected);
  EXPECT_FALSE(result.second.hasValue());
}

TEST_F(AeadTicketCipherTest, TestDecryptSeqNum) {
  setTicketSecrets();
  expectDecode();
  auto result = cipher_.decrypt(toIOBuf(ticket2)).get();
  EXPECT_EQ(result.first, PskType::Resumption);
  EXPECT_TRUE(result.second.hasValue());
}

TEST_F(AeadTicketCipherTest, TestDecryptFailed) {
  setTicketSecrets();
  auto result = cipher_.decrypt(toIOBuf(badTicket)).get();
  EXPECT_EQ(result.first, PskType::Rejected);
  EXPECT_FALSE(result.second.hasValue());
}

TEST_F(AeadTicketCipherTest, TestDecryptTooShort) {
  setTicketSecrets();
  auto result = cipher_.decrypt(IOBuf::copyBuffer("short")).get();
  EXPECT_EQ(result.first, PskType::Rejected);
  EXPECT_FALSE(result.second.hasValue());
}

TEST_F(AeadTicketCipherTest, TestUnsetTicketSecrets) {
  setTicketSecrets();
  EXPECT_TRUE(cipher_.setTicketSecrets(std::vector<ByteRange>()));
  checkUnsetEncrypt();
}

TEST_F(AeadTicketCipherTest, TestSetTicketSecretsTooShort) {
  StringPiece tooShort{"short"};
  std::vector<ByteRange> ticketSecrets{{tooShort}};
  EXPECT_FALSE(cipher_.setTicketSecrets(std::move(ticketSecrets)));
  checkUnsetEncrypt();
}
} // namespace test
} // namespace server
} // namespace fizz
