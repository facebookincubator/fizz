// Copyright 2004-present Facebook. All Rights Reserved.
#include <vector>

#include <folly/Benchmark.h>
#include <folly/Random.h>
#include <folly/init/Init.h>

#include <fizz/crypto/Utils.h>
#include <fizz/crypto/aead/AESGCM128.h>
#include <fizz/crypto/aead/AESOCB128.h>
#include <fizz/crypto/aead/OpenSSLEVPCipher.h>
#include <fizz/record/EncryptedRecordLayer.h>

using namespace fizz;

std::unique_ptr<folly::IOBuf> makeRandom(size_t n) {
  static const char alphanum[] =
      "0123456789"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz";

  std::string rv;
  rv.reserve(n);
  for (size_t i = 0; i < n; ++i) {
    rv.push_back(alphanum[folly::Random::rand32() % (sizeof(alphanum) - 1)]);
  }
  return folly::IOBuf::copyBuffer(rv, 5, 17);
}

std::unique_ptr<folly::IOBuf> toIOBuf(std::string hexData) {
  std::string out;
  CHECK(folly::unhexlify(hexData, out));
  return folly::IOBuf::copyBuffer(out);
}

TrafficKey getKey() {
  TrafficKey trafficKey;
  trafficKey.key = toIOBuf("000102030405060708090A0B0C0D0E0F");
  trafficKey.iv = toIOBuf("000102030405060708090A0B");
  return trafficKey;
}

void encryptGCM(uint32_t n, size_t size) {
  std::unique_ptr<Aead> aead;
  std::vector<fizz::TLSMessage> msgs;
  EncryptedWriteRecordLayer write{EncryptionLevel::AppTraffic};
  BENCHMARK_SUSPEND {
    aead = std::make_unique<OpenSSLEVPCipher<AESGCM128>>();
    aead->setKey(getKey());
    write.setAead(std::move(aead));
    for (size_t i = 0; i < n; ++i) {
      TLSMessage msg{ContentType::application_data, makeRandom(size)};
      msgs.push_back(std::move(msg));
    }
  }

  std::unique_ptr<folly::IOBuf> buf;
  for (auto& msg : msgs) {
    buf = write.write(std::move(msg));
  }
  doNotOptimizeAway(buf);
}

BENCHMARK_PARAM(encryptGCM, 10);
BENCHMARK_PARAM(encryptGCM, 100);
BENCHMARK_PARAM(encryptGCM, 1000);
BENCHMARK_PARAM(encryptGCM, 4000);
BENCHMARK_PARAM(encryptGCM, 8000);

#if FOLLY_OPENSSL_IS_110 && !defined(OPENSSL_NO_OCB)
void encryptOCB(uint32_t n, size_t size) {
  std::unique_ptr<Aead> aead;
  std::vector<fizz::TLSMessage> msgs;
  EncryptedWriteRecordLayer write{EncryptionLevel::AppTraffic};
  BENCHMARK_SUSPEND {
    aead = std::make_unique<OpenSSLEVPCipher<AESOCB128>>();
    aead->setKey(getKey());
    write.setAead(std::move(aead));
    for (size_t i = 0; i < n; ++i) {
      TLSMessage msg{ContentType::application_data, makeRandom(size)};
      msgs.push_back(std::move(msg));
    }
  }

  std::unique_ptr<folly::IOBuf> buf;
  for (auto& msg : msgs) {
    buf = write.write(std::move(msg));
  }
  doNotOptimizeAway(buf);
}

BENCHMARK_PARAM(encryptOCB, 10);
BENCHMARK_PARAM(encryptOCB, 100);
BENCHMARK_PARAM(encryptOCB, 1000);
BENCHMARK_PARAM(encryptOCB, 4000);
BENCHMARK_PARAM(encryptOCB, 8000);
#endif

int main(int argc, char** argv) {
  folly::init(&argc, &argv);
  CryptoUtils::init();
  folly::runBenchmarks();
  return 0;
}
